//! Passkey 认证、challenge 和限流编排；注册流程放在 `passkey_registration`。

use webauthn_rs::prelude::PublicKeyCredential;
use webauthn_rs_core::proto::RequestChallengeResponse;

use super::{
    AuthFactorService, AuthFactorServiceError, PasskeyConfirmation,
    passkey_core::{
        PendingPasskeyAuthentication, build_core, core_credential, user_verification_policy,
    },
};
use crate::{
    auth_factors::{
        domain::{FactorMethod, LoginTicket},
        persistence::consume_then_persist,
        repository,
    },
    auth_limiter::{AuthReservation, FailureDimension},
    users::domain::UserId,
};

#[path = "passkey_registration.rs"]
mod registration;

const PASSKEY_REGISTRATION_PREFIX: &str = "chenxing:auth:passkey-registration:";
const PASSKEY_AUTHENTICATION_PREFIX: &str = "chenxing:auth:passkey-authentication:";
impl AuthFactorService {
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

    pub async fn start_passkey_authentication(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        source_ip: Option<&str>,
    ) -> Result<Option<RequestChallengeResponse>, AuthFactorServiceError> {
        let (settings, issuer_generation) = self.enabled_passkey_settings_with_generation().await?;
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
        // authentication challenge/state，竞态败者复用胜者的 challenge，绝不覆盖胜者状态。
        let reserved = self
            .tickets
            .save_json_if_absent(
                &self.passkey_authentication_key(ticket_id),
                &PendingPasskeyAuthentication {
                    user_id: ticket.user_id,
                    state,
                    settings,
                    issuer_generation: Some(issuer_generation),
                    challenge: Some(challenge.clone()),
                    credential_row_ids,
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        if reserved {
            return Ok(Some(challenge));
        }
        // A browser may cancel the ceremony after start. Reuse the still-valid
        // reservation rather than issuing a second state or burning a
        // credential on an ordinary retry. Legacy reservations without the
        // serialized options fail closed and wait for their TTL to expire.
        Ok(self
            .tickets
            .find_json::<PendingPasskeyAuthentication>(&self.passkey_authentication_key(ticket_id))
            .await?
            .and_then(|pending| pending.challenge))
    }

    pub async fn finish_passkey_authentication(
        &self,
        ticket_id: &str,
        holder_hash: &str,
        source_ip: Option<&str>,
        credential: &PublicKeyCredential,
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
            .find_json::<PendingPasskeyAuthentication>(&self.passkey_authentication_key(ticket_id))
            .await?
        else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        if pending.user_id != ticket.user_id {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        if pending.issuer_generation != Some(current_issuer_generation) {
            self.tickets
                .delete(&self.passkey_authentication_key(ticket_id))
                .await?;
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        // 预留额度必须在 authenticate_credential 验签之前：challenge 是一次性的，但同一个
        // ticket 在 5 分钟 TTL 内可以反复提交伪造 credential，每次都会付出一轮验签代价。
        let account_key = self.account_key(ticket.user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        let Some(reservation) = self.ensure_dimensions_allowed(dimensions.clone()).await? else {
            return Ok(PasskeyConfirmation::RateLimited(ticket.user_id));
        };
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
                        reservation,
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
                    reservation,
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
                    repository::PasskeyPersistOutcome::CounterConflict => {
                        // 先释放旧 challenge，再由 consume_then_persist 恢复 ticket。
                        // 下一次 start 必须生成新状态，不能把用户困在旧计数快照里。
                        self.tickets
                            .delete(&self.passkey_authentication_key(ticket_id))
                            .await?;
                        Err(AuthFactorServiceError::PasskeyCounterConflict)
                    }
                    repository::PasskeyPersistOutcome::Missing
                    | repository::PasskeyPersistOutcome::Exhausted => {
                        // 行身份失效或 CAS 耗尽时也释放旧预留，重试必须绑定当前凭据行。
                        self.tickets
                            .delete(&self.passkey_authentication_key(ticket_id))
                            .await?;
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
        reservation: AuthReservation,
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
