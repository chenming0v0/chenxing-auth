//! Passkey 注册与认证的用例流程：ticket 校验、失败限流、challenge 状态存取和
//! 凭据持久化。WebAuthn 协议与配置翻译放在 `passkey_core`。

use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, COSEAlgorithm, CreationChallengeResponse,
    RequestChallengeResponse,
};

use super::{
    AuthFactorService, AuthFactorServiceError, PasskeyConfirmation,
    passkey_core::{
        PendingPasskeyAuthentication, PendingPasskeyRegistration, authenticator_attachment,
        build_core, core_credential, passkey_from_credential, passkey_registration_extensions,
        user_verification_policy,
    },
};
use crate::{
    auth_factors::{
        domain::{FactorMethod, LoginTicket},
        persistence::consume_then_persist,
        repository,
    },
    auth_limiter::{FailureDimension, LimiterDimension},
    users::domain::UserId,
};

const PASSKEY_REGISTRATION_PREFIX: &str = "chenxing:auth:passkey-registration:";
const PASSKEY_AUTHENTICATION_PREFIX: &str = "chenxing:auth:passkey-authentication:";

impl AuthFactorService {
    async fn enabled_passkey_settings(
        &self,
    ) -> Result<crate::settings::PasskeySetting, AuthFactorServiceError> {
        let settings = self.settings.passkey().await?;
        if settings.enabled {
            Ok(settings)
        } else {
            Err(AuthFactorServiceError::PasskeyDisabled)
        }
    }

    pub async fn start_passkey_registration(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        source_ip: Option<&str>,
        user_name: &str,
        display_name: &str,
    ) -> Result<Option<CreationChallengeResponse>, AuthFactorServiceError> {
        let settings = self.enabled_passkey_settings().await?;
        let Some(ticket) = self.tickets.find_for_holder(ticket_id, holder_hash).await? else {
            return Ok(None);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Passkey)
        {
            return Ok(None);
        }
        // 限流检查必须在 list_factor_methods / list_passkeys 之前：challenge 端点用同一个
        // ticket 可以在 TTL 内无限重放，先查库会让攻击者用廉价请求放大数据库负载。
        self.ensure_passkey_attempt_allowed(ticket.user_id, ticket_id, source_ip)
            .await?;
        if !repository::list_factor_methods(&self.pool, ticket.user_id)
            .await?
            .is_empty()
        {
            return Ok(None);
        }
        let existing = repository::list_passkeys(&self.pool, ticket.user_id).await?;
        let exclude = Some(
            existing
                .iter()
                .map(|passkey| passkey.cred_id().clone())
                .collect(),
        );
        let core = build_core(&settings)?;
        let builder = core
            .new_challenge_register_builder(
                Uuid::from_u128(ticket.user_id as u128).as_bytes(),
                user_name,
                display_name,
            )?
            .attestation(AttestationConveyancePreference::None)
            .credential_algorithms(COSEAlgorithm::secure_algs())
            .require_resident_key(false)
            .authenticator_attachment(authenticator_attachment(&settings))
            .user_verification_policy(user_verification_policy(&settings))
            .reject_synchronised_authenticators(false)
            .exclude_credentials(exclude)
            .hints(None)
            .extensions(Some(passkey_registration_extensions()));
        let (challenge, state) = core.generate_challenge_register(builder)?;
        self.tickets
            .save_json(
                &Self::passkey_registration_key(ticket_id),
                &PendingPasskeyRegistration {
                    user_id: ticket.user_id,
                    state,
                    settings,
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(Some(challenge))
    }

    pub async fn finish_passkey_registration(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        source_ip: Option<&str>,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<PasskeyConfirmation, AuthFactorServiceError> {
        self.enabled_passkey_settings().await?;
        let Some(ticket) = self.tickets.find_for_holder(ticket_id, holder_hash).await? else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Passkey)
        {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        let Some(pending) = self
            .tickets
            .find_json::<PendingPasskeyRegistration>(&Self::passkey_registration_key(ticket_id))
            .await?
        else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        if pending.user_id != ticket.user_id {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        // 预留额度必须在 WebAuthn 验签和写库之前完成，否则伪造 credential 可以在 ticket TTL
        // 内反复触发证明解析与数据库写入，限流也就防不住计算放大。
        let account_key = self.account_key(ticket.user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Ok(PasskeyConfirmation::RateLimited(ticket.user_id));
        }
        let core = match build_core(&pending.settings) {
            Ok(core) => core,
            Err(error) => {
                self.release_dimensions(dimensions).await?;
                return Err(error);
            }
        };
        let credential = match core.register_credential(credential, &pending.state, None) {
            Ok(credential) => credential,
            Err(_) => {
                return self
                    .record_passkey_failure(
                        ticket_id,
                        holder_hash,
                        ticket.user_id,
                        &Self::passkey_registration_key(ticket_id),
                        dimensions,
                    )
                    .await;
            }
        };
        let passkey = match passkey_from_credential(credential) {
            Ok(passkey) => passkey,
            Err(error) => {
                self.release_dimensions(dimensions).await?;
                return Err(error);
            }
        };
        // 验签通过即视为一次成功尝试，先归还预留额度再消费 ticket，避免额度悬挂。
        self.release_dimensions(dimensions).await?;
        self.limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await?;
        let confirmation = match consume_then_persist(
            PasskeyConfirmation::Completed(ticket.user_id),
            PasskeyConfirmation::InvalidTicket,
            self.tickets.take_for_holder(ticket_id, holder_hash),
            async {
                match repository::insert_passkey_if_empty(
                    &self.pool,
                    ticket.user_id,
                    passkey.cred_id(),
                    &passkey,
                )
                .await?
                {
                    repository::PasskeyPersistenceResult::Stored => Ok(()),
                    repository::PasskeyPersistenceResult::Conflict => {
                        Err(AuthFactorServiceError::FirstFactorAlreadyExists)
                    }
                }
            },
            |ticket| self.tickets.restore(ticket_id, ticket),
        )
        .await
        {
            Ok(confirmation) => confirmation,
            Err(AuthFactorServiceError::FirstFactorAlreadyExists) => {
                let _ = self
                    .tickets
                    .take_for_holder(ticket_id, holder_hash)
                    .await?;
                self.tickets
                    .delete(&Self::passkey_registration_key(ticket_id))
                    .await?;
                return Ok(PasskeyConfirmation::InvalidTicket);
            }
            Err(error) => return Err(error),
        };
        if matches!(confirmation, PasskeyConfirmation::InvalidTicket) {
            return Ok(confirmation);
        }
        self.tickets
            .delete(&Self::passkey_registration_key(ticket_id))
            .await?;
        Ok(confirmation)
    }

    pub async fn start_passkey_authentication(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        source_ip: Option<&str>,
    ) -> Result<Option<RequestChallengeResponse>, AuthFactorServiceError> {
        let settings = self.enabled_passkey_settings().await?;
        let Some(ticket) = self.tickets.find_for_holder(ticket_id, holder_hash).await? else {
            return Ok(None);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Passkey)
        {
            return Ok(None);
        }
        // 同一个 ticket 可以反复请求 challenge，限流检查必须挡在 list_passkeys 之前。
        self.ensure_passkey_attempt_allowed(ticket.user_id, ticket_id, source_ip)
            .await?;
        let passkeys = repository::list_passkeys(&self.pool, ticket.user_id).await?;
        if passkeys.is_empty() {
            return Ok(None);
        }
        let credentials = passkeys
            .iter()
            .map(core_credential)
            .collect::<Result<Vec<_>, _>>()?;
        let core = build_core(&settings)?;
        let builder = core
            .new_challenge_authenticate_builder(
                credentials,
                Some(user_verification_policy(&settings)),
            )?
            .extensions(None)
            .allow_backup_eligible_upgrade(true)
            .hints(None);
        let (challenge, state) = core.generate_challenge_authenticate(builder)?;
        self.tickets
            .save_json(
                &Self::passkey_authentication_key(ticket_id),
                &PendingPasskeyAuthentication {
                    user_id: ticket.user_id,
                    state,
                    settings,
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(Some(challenge))
    }

    pub async fn finish_passkey_authentication(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        source_ip: Option<&str>,
        credential: &PublicKeyCredential,
    ) -> Result<PasskeyConfirmation, AuthFactorServiceError> {
        self.enabled_passkey_settings().await?;
        let Some(ticket) = self.tickets.find_for_holder(ticket_id, holder_hash).await? else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Passkey)
        {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        let Some(pending) = self
            .tickets
            .find_json::<PendingPasskeyAuthentication>(&Self::passkey_authentication_key(ticket_id))
            .await?
        else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        if pending.user_id != ticket.user_id {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        // 预留额度必须在 authenticate_credential 验签和 list_passkeys 查询之前：challenge 是
        // 一次性的，但同一个 ticket 在 5 分钟 TTL 内可以反复提交伪造 credential，每次都会付出
        // 一轮验签与数据库查询的代价。
        let account_key = self.account_key(ticket.user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Ok(PasskeyConfirmation::RateLimited(ticket.user_id));
        }
        let core = match build_core(&pending.settings) {
            Ok(core) => core,
            Err(error) => {
                self.release_dimensions(dimensions).await?;
                return Err(error);
            }
        };
        let result = match core.authenticate_credential(credential, &pending.state) {
            Ok(result) => result,
            Err(_) => {
                return self
                    .record_passkey_failure(
                        ticket_id,
                        holder_hash,
                        ticket.user_id,
                        &Self::passkey_authentication_key(ticket_id),
                        dimensions,
                    )
                    .await;
            }
        };
        let mut passkeys = match repository::list_passkeys(&self.pool, ticket.user_id).await {
            Ok(passkeys) => passkeys,
            Err(error) => {
                self.release_dimensions(dimensions).await?;
                return Err(error.into());
            }
        };
        let Some(passkey) = passkeys
            .iter_mut()
            .find(|passkey| passkey.cred_id() == result.cred_id())
        else {
            return self
                .record_passkey_failure(
                    ticket_id,
                    holder_hash,
                    ticket.user_id,
                    &Self::passkey_authentication_key(ticket_id),
                    dimensions,
                )
                .await;
        };
        // 验签与凭据匹配都通过，先归还预留额度并清空 ticket 维度计数，再消费 ticket。
        self.release_dimensions(dimensions).await?;
        self.limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await?;
        let confirmation = consume_then_persist(
            PasskeyConfirmation::Completed(ticket.user_id),
            PasskeyConfirmation::InvalidTicket,
            self.tickets.take_for_holder(ticket_id, holder_hash),
            async {
                if result.needs_update()
                    && passkey
                        .update_credential(&result)
                        .is_some_and(|changed| changed)
                {
                    repository::update_passkey(&self.pool, result.cred_id(), passkey).await?;
                }
                Ok::<(), AuthFactorServiceError>(())
            },
            |ticket| self.tickets.restore(ticket_id, ticket),
        )
        .await?;
        if matches!(confirmation, PasskeyConfirmation::InvalidTicket) {
            return Ok(confirmation);
        }
        self.tickets
            .delete(&Self::passkey_authentication_key(ticket_id))
            .await?;
        Ok(confirmation)
    }

    /// Challenge 端点不提交凭据，因此只做无副作用的额度检查，不预留也不记失败；
    /// 预留会在这些不返回结果的路径上悬挂 pending 计数，直到窗口过期。
    async fn ensure_passkey_attempt_allowed(
        &self,
        user_id: UserId,
        ticket_id: &str,
        source_ip: Option<&str>,
    ) -> Result<(), AuthFactorServiceError> {
        let account_key = self.account_key(user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        if self.limiter.any_limited(dimensions).await? {
            return Err(AuthFactorServiceError::RateLimited);
        }
        Ok(())
    }

    /// 记录一次 Passkey 失败尝试。ticket 维度达阈值时立即失效 ticket 和挂起的
    /// challenge 状态，让被爆破的登录流程无法继续复用。
    async fn record_passkey_failure(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        user_id: UserId,
        pending_key: &str,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<PasskeyConfirmation, AuthFactorServiceError> {
        let record = self.record_failure(dimensions).await?;
        if record.reached(FailureDimension::Ticket) {
            self.invalidate_ticket(ticket_id, holder_hash).await?;
            self.tickets.delete(pending_key).await?;
            return Ok(PasskeyConfirmation::RateLimited(user_id));
        }
        if !record.reached.is_empty() {
            return Ok(PasskeyConfirmation::RateLimited(user_id));
        }
        Ok(PasskeyConfirmation::InvalidCredential(user_id))
    }

    fn passkey_registration_key(ticket_id: &str) -> String {
        format!("{PASSKEY_REGISTRATION_PREFIX}{ticket_id}")
    }

    fn passkey_authentication_key(ticket_id: &str) -> String {
        format!("{PASSKEY_AUTHENTICATION_PREFIX}{ticket_id}")
    }
}
