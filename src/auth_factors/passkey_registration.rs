use uuid::Uuid;
use webauthn_rs::prelude::RegisterPublicKeyCredential;
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, COSEAlgorithm, CreationChallengeResponse,
};

use super::super::passkey_core::{
    PendingPasskeyRegistration, authenticator_attachment, build_core, passkey_from_credential,
    user_verification_policy,
};
use super::{AuthFactorService, AuthFactorServiceError, PasskeyConfirmation};
use crate::{
    auth_factors::{
        domain::{FactorMethod, LoginTicket},
        persistence::consume_then_persist,
        repository,
    },
    auth_limiter::FailureDimension,
};

impl AuthFactorService {
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
        };
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
                        reservation,
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
                    ticket.session_epoch,
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
                    repository::PasskeyPersistenceResult::AuthenticationChanged => {
                        Err(AuthFactorServiceError::AuthenticationEpochChanged)
                    }
                }
            },
            |ticket| self.tickets.restore(ticket_id, ticket),
        )
        .await
        {
            Ok(confirmation) => confirmation,
            Err(
                AuthFactorServiceError::FirstFactorAlreadyExists
                | AuthFactorServiceError::AuthenticationEpochChanged,
            ) => {
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
}
