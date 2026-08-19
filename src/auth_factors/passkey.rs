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
        build_core, core_credential, passkey_from_credential, user_verification_policy,
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
    pub(super) async fn enabled_passkey_settings(
        &self,
    ) -> Result<crate::settings::PasskeySetting, AuthFactorServiceError> {
        Ok(self.enabled_passkey_settings_with_generation().await?.0)
    }

    pub(super) async fn enabled_passkey_settings_with_generation(
        &self,
    ) -> Result<(crate::settings::PasskeySetting, i64), AuthFactorServiceError> {
        let (settings, generation) = self.settings.passkey_with_issuer_binding().await?;
        if settings.enabled {
            Ok((settings, generation.unwrap_or_default()))
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
        let (settings, issuer_generation) = self.enabled_passkey_settings_with_generation().await?;
        let Some(ticket) = self.tickets.find_for_holder(ticket_id, holder_hash).await? else {
            return Ok(None);
        };
        if !ticket.is_active_at(self.clock.now()) || !ticket.supports(FactorMethod::Passkey) {
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
            .require_resident_key(true)
            .authenticator_attachment(authenticator_attachment(&settings))
            .user_verification_policy(user_verification_policy(&settings))
            .reject_synchronised_authenticators(false)
            .exclude_credentials(exclude)
            .hints(None)
            .extensions(None);
        let (challenge, state) = core.generate_challenge_register(builder)?;
        // Challenge 和校验状态是一对不可拆分的一次性材料。用 SET NX EX 原子预留，
        // 确保重复或并发 start 的败者不会用新状态覆盖已经返回给胜者的 challenge。
        // `ensure_passkey_attempt_allowed` 只检查额度，因此预留失败也不会烧毁失败计数。
        let reserved = self
            .tickets
            .save_json_if_absent(
                &self.passkey_registration_key(ticket_id),
                &PendingPasskeyRegistration {
                    user_id: ticket.user_id,
                    state,
                    settings,
                    issuer_generation: Some(issuer_generation),
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(reserved.then_some(challenge))
    }

    pub async fn finish_passkey_registration(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        source_ip: Option<&str>,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<PasskeyConfirmation, AuthFactorServiceError> {
        let (_, current_issuer_generation) =
            self.enabled_passkey_settings_with_generation().await?;
        let Some(ticket) = self.tickets.find_for_holder(ticket_id, holder_hash).await? else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        if !ticket.is_active_at(self.clock.now()) || !ticket.supports(FactorMethod::Passkey) {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        let Some(pending) = self
            .tickets
            .find_json::<PendingPasskeyRegistration>(&self.passkey_registration_key(ticket_id))
            .await?
        else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        if pending.user_id != ticket.user_id {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        if pending.issuer_generation != Some(current_issuer_generation) {
            self.tickets
                .delete(&self.passkey_registration_key(ticket_id))
                .await?;
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        // 预留额度必须在 WebAuthn 验签和写库之前完成，否则伪造 credential 可以在 ticket TTL
        // 内反复触发证明解析与数据库写入，限流也就防不住计算放大。
        let account_key = self.account_key(ticket.user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        let Some(reservation) = self.ensure_dimensions_allowed(dimensions.clone()).await? else {
            return Ok(PasskeyConfirmation::RateLimited(ticket.user_id));
        }
        let core = match build_core(&pending.settings) {
            Ok(core) => core,
            Err(error) => {
                self.release_dimensions(reservation).await?;
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
                        &self.passkey_registration_key(ticket_id),
                        dimensions,
                    )
                    .await;
            }
        };
        let passkey = match passkey_from_credential(credential) {
            Ok(passkey) => passkey,
            Err(error) => {
                self.release_dimensions(reservation).await?;
                return Err(error);
            }
        };
        // 验签通过即视为一次成功尝试，先归还预留额度再消费 ticket，避免额度悬挂。
        self.release_dimensions(reservation).await?;
        self.limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await?;
        let confirmation = match consume_then_persist(
            PasskeyConfirmation::Completed(ticket.authenticated()),
            PasskeyConfirmation::InvalidTicket,
            self.tickets.take_for_holder(ticket_id, holder_hash),
            async {
                match repository::insert_passkey_if_empty_with_issuer_generation(
                    &self.pool,
                    ticket.user_id,
                    passkey.cred_id(),
                    &passkey,
                    current_issuer_generation,
                )
                .await?
                {
                    repository::PasskeyPersistenceResult::Stored => Ok(()),
                    repository::PasskeyPersistenceResult::Conflict
                    | repository::PasskeyPersistenceResult::IssuerChanged => {
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
                let _ = self.tickets.take_for_holder(ticket_id, holder_hash).await?;
                self.tickets
                    .delete(&self.passkey_registration_key(ticket_id))
                    .await?;
                return Ok(PasskeyConfirmation::InvalidTicket);
            }
            Err(error) => return Err(error),
        };
        if matches!(confirmation, PasskeyConfirmation::InvalidTicket) {
            return Ok(confirmation);
        }
        self.tickets
            .delete(&self.passkey_registration_key(ticket_id))
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
        if !ticket.is_active_at(self.clock.now()) || !ticket.supports(FactorMethod::Passkey) {
            return Ok(None);
        }
        // 同一个 ticket 可以反复请求 challenge，限流检查必须挡在 list_passkeys 之前。
        self.ensure_passkey_attempt_allowed(ticket.user_id, ticket_id, source_ip)
            .await?;
        let passkeys = repository::list_passkeys_with_versions(&self.pool, ticket.user_id).await?;
        if passkeys.is_empty() {
            return Ok(None);
        }
        let credentials = passkeys
            .iter()
            .map(|passkey| core_credential(passkey.passkey()))
            .collect::<Result<Vec<_>, _>>()?;
        let credential_row_ids = passkeys
            .iter()
            .map(|passkey| (passkey.credential_id.clone(), passkey.id))
            .collect();
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
        // 与注册路径使用同一个原子预留语义：同一 ticket 只能有一份已签发的
        // authentication challenge/state，竞态败者明确返回 None，绝不覆盖胜者状态。
        let reserved = self
            .tickets
            .save_json_if_absent(
                &self.passkey_authentication_key(ticket_id),
                &PendingPasskeyAuthentication {
                    user_id: ticket.user_id,
                    state,
                    settings,
                    credential_row_ids,
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(reserved.then_some(challenge))
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
        if !ticket.is_active_at(self.clock.now()) || !ticket.supports(FactorMethod::Passkey) {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        let Some(pending) = self
            .tickets
            .find_json::<PendingPasskeyAuthentication>(&self.passkey_authentication_key(ticket_id))
            .await?
        else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        if pending.user_id != ticket.user_id {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        // 预留额度必须在 authenticate_credential 验签之前：challenge 是一次性的，但同一个
        // ticket 在 5 分钟 TTL 内可以反复提交伪造 credential，每次都会付出一轮验签代价。
        let account_key = self.account_key(ticket.user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        let Some(reservation) = self.ensure_dimensions_allowed(dimensions.clone()).await? else {
            return Ok(PasskeyConfirmation::RateLimited(ticket.user_id));
        }
        let core = match build_core(&pending.settings) {
            Ok(core) => core,
            Err(error) => {
                self.release_dimensions(reservation).await?;
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
                        &self.passkey_authentication_key(ticket_id),
                        dimensions,
                    )
                    .await;
            }
        };
        // 行身份来自签发 challenge 时的快照，不按 finish 当下的 credential_id 重查。
        // 没有绑定（旧 pending 或凭据不在 challenge 集合里）按验签失败处理。
        let Some(row_id) = pending.row_id_for(result.cred_id()) else {
            return self
                .record_passkey_failure(
                    ticket_id,
                    holder_hash,
                    ticket.user_id,
                    &self.passkey_authentication_key(ticket_id),
                    dimensions,
                )
                .await;
        };
        // 验签与凭据匹配都通过，先归还预留额度并清空 ticket 维度计数，再消费 ticket。
        self.release_dimensions(reservation).await?;
        self.limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await?;
        let confirmation = consume_then_persist(
            PasskeyConfirmation::Completed(ticket.authenticated()),
            PasskeyConfirmation::InvalidTicket,
            self.tickets.take_for_holder(ticket_id, holder_hash),
            async {
                match repository::persist_passkey_authentication(
                    &self.pool,
                    ticket.user_id,
                    row_id,
                    result.cred_id(),
                    &result,
                )
                .await?
                {
                    repository::PasskeyPersistOutcome::Applied
                    | repository::PasskeyPersistOutcome::AlreadyCurrent => Ok(()),
                    repository::PasskeyPersistOutcome::Missing
                    | repository::PasskeyPersistOutcome::Exhausted => {
                        Err(AuthFactorServiceError::PasskeyUpdateConflict)
                    }
                }
            },
            |ticket| self.tickets.restore(ticket_id, ticket),
        )
        .await?;
        if matches!(confirmation, PasskeyConfirmation::InvalidTicket) {
            return Ok(confirmation);
        }
        self.tickets
            .delete(&self.passkey_authentication_key(ticket_id))
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
        let record = self.record_failure(reservation).await?;
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

    fn passkey_registration_key(&self, ticket_id: &str) -> String {
        self.tickets
            .namespaced(&format!("{PASSKEY_REGISTRATION_PREFIX}{ticket_id}"))
    }

    fn passkey_authentication_key(&self, ticket_id: &str) -> String {
        self.tickets
            .namespaced(&format!("{PASSKEY_AUTHENTICATION_PREFIX}{ticket_id}"))
    }
}
