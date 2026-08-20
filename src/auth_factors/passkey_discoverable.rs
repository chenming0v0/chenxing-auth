use uuid::Uuid;
use webauthn_rs::prelude::PublicKeyCredential;
use webauthn_rs_core::proto::{RequestChallengeResponse, UserVerificationPolicy};

use super::{
    AuthFactorService, AuthFactorServiceError,
    passkey_core::{build_core, core_credential},
};
use crate::{
    auth_factors::{domain::LoginTicket, repository},
    auth_limiter::{AuthReservation, FailureDimension, MissingSourceIpPolicy},
};

const DISCOVERABLE_PASSKEY_PREFIX: &str = "chenxing:auth:passkey-discoverable:";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingDiscoverablePasskeyAuthentication {
    state: webauthn_rs_core::proto::AuthenticationState,
    settings: crate::settings::PasskeySetting,
    expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverablePasskeyConfirmation {
    Invalid,
    RateLimited,
    Completed(crate::users::domain::AuthenticatedUser),
}

impl AuthFactorService {
    pub async fn start_discoverable_passkey_authentication(
        &self,
        source_ip: Option<&str>,
    ) -> Result<Option<(String, RequestChallengeResponse)>, AuthFactorServiceError> {
        let settings = self.enabled_passkey_settings().await?;
        match (source_ip, self.missing_source_ip_policy) {
            (Some(source_ip), _) => {
                if self
                    .limiter
                    .is_limited(FailureDimension::SourceIp, source_ip)
                    .await?
                {
                    return Err(AuthFactorServiceError::RateLimited);
                }
            }
            (None, MissingSourceIpPolicy::Skip) => tracing::warn!(
                event = "auth_limiter.source_ip_unavailable",
                policy = MissingSourceIpPolicy::Skip.as_str(),
                "discoverable Passkey start is proceeding without an IP dimension"
            ),
            (None, MissingSourceIpPolicy::Reject) => {
                return Err(AuthFactorServiceError::SourceIpUnavailable);
            }
        }
        let core = build_core(&settings)?;
        let builder = core
            .new_challenge_authenticate_builder(Vec::new(), Some(UserVerificationPolicy::Required))?
            .extensions(None)
            .allow_backup_eligible_upgrade(false)
            .hints(None);
        let (challenge, state) = core.generate_challenge_authenticate(builder)?;
        let challenge_id = Uuid::new_v4().to_string();
        let reserved = self
            .tickets
            .save_json_if_absent(
                &self.discoverable_passkey_key(&challenge_id),
                &PendingDiscoverablePasskeyAuthentication {
                    state,
                    settings,
                    expires_at: self.clock.now() + LoginTicket::TTL,
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(reserved.then_some((challenge_id, challenge)))
    }

    pub async fn finish_discoverable_passkey_authentication(
        &self,
        challenge_id: &str,
        source_ip: Option<&str>,
        credential: &PublicKeyCredential,
    ) -> Result<DiscoverablePasskeyConfirmation, AuthFactorServiceError> {
        let key = self.discoverable_passkey_key(challenge_id);
        let Some(pending) = self
            .tickets
            .find_json::<PendingDiscoverablePasskeyAuthentication>(&key)
            .await?
        else {
            return Ok(DiscoverablePasskeyConfirmation::Invalid);
        };
        let Some(user_handle) = credential.get_user_unique_id() else {
            return self.unidentified_discoverable_failure(source_ip).await;
        };
        let Ok(user_uuid) = Uuid::from_slice(user_handle) else {
            return self.unidentified_discoverable_failure(source_ip).await;
        };
        let user_id = user_uuid.as_u128();
        if user_id > i64::MAX as u128 {
            return self.unidentified_discoverable_failure(source_ip).await;
        }
        let user_id = user_id as i64;
        let account_key = match self.account_key(user_id).await {
            Ok(account_key) => account_key,
            Err(AuthFactorServiceError::UserNotFound) => {
                return self.unidentified_discoverable_failure(source_ip).await;
            }
            Err(error) => return Err(error),
        };
        let dimensions = self.failure_dimensions(&account_key, None, source_ip)?;
        let Some(reservation) = self.ensure_dimensions_allowed(dimensions.clone()).await? else {
            return Ok(DiscoverablePasskeyConfirmation::RateLimited);
        };
        let passkeys = match repository::list_passkeys_with_versions(&self.pool, user_id).await {
            Ok(passkeys) => passkeys,
            Err(error) => {
                self.release_dimensions_after_error(reservation).await;
                return Err(error.into());
            }
        };
        let Some(stored) = passkeys
            .into_iter()
            .find(|p| p.credential_id == credential.get_credential_id())
        else {
            return self.discoverable_failure(reservation).await;
        };
        let stored_credential = match core_credential(stored.passkey()) {
            Ok(credential) => credential,
            Err(error) => {
                self.release_dimensions_after_error(reservation).await;
                return Err(error);
            }
        };
        let core = match build_core(&pending.settings) {
            Ok(core) => core,
            Err(error) => {
                self.release_dimensions_after_error(reservation).await;
                return Err(error);
            }
        };
        let mut state = pending.state;
        state.set_allowed_credentials(vec![stored_credential]);
        let result = match core.authenticate_credential(credential, &state) {
            Ok(result) => result,
            Err(_) => return self.discoverable_failure(reservation).await,
        };
        let epoch =
            match crate::users::repository::find_active_session_epoch(&self.pool, user_id).await {
                Ok(Some(epoch)) => epoch,
                Ok(None) => {
                    self.release_dimensions(reservation).await?;
                    return Ok(DiscoverablePasskeyConfirmation::Invalid);
                }
                Err(error) => {
                    self.release_dimensions_after_error(reservation).await;
                    return Err(error.into());
                }
            };
        let consumed = match self
            .tickets
            .take_json::<PendingDiscoverablePasskeyAuthentication>(&key)
            .await
        {
            Ok(Some(consumed)) => consumed,
            Ok(None) => {
                self.release_dimensions(reservation).await?;
                return Ok(DiscoverablePasskeyConfirmation::Invalid);
            }
            Err(error) => {
                self.release_dimensions_after_error(reservation).await;
                return Err(error.into());
            }
        };
        let persisted = repository::persist_passkey_authentication(
            &self.pool,
            user_id,
            stored.id,
            result.cred_id(),
            &result,
        )
        .await;
        let outcome = match persisted {
            Ok(outcome) => outcome,
            Err(error) => {
                self.restore_discoverable_after_error(&key, &consumed).await;
                self.release_dimensions_after_error(reservation).await;
                return Err(error.into());
            }
        };
        match outcome {
            repository::PasskeyPersistOutcome::Applied
            | repository::PasskeyPersistOutcome::AlreadyCurrent => {}
            repository::PasskeyPersistOutcome::Missing => {
                self.release_dimensions(reservation).await?;
                return Ok(DiscoverablePasskeyConfirmation::Invalid);
            }
            repository::PasskeyPersistOutcome::Exhausted => {
                self.restore_discoverable_after_error(&key, &consumed).await;
                self.release_dimensions_after_error(reservation).await;
                return Err(AuthFactorServiceError::PasskeyUpdateConflict);
            }
        }
        self.release_dimensions(reservation.clone()).await?;
        for (dimension, value) in dimensions {
            self.limiter.clear(dimension, &value).await?;
        }
        Ok(DiscoverablePasskeyConfirmation::Completed(
            crate::users::domain::AuthenticatedUser::new(user_id, epoch),
        ))
    }

    async fn discoverable_failure(
        &self,
        reservation: AuthReservation,
    ) -> Result<DiscoverablePasskeyConfirmation, AuthFactorServiceError> {
        if self.record_failure(reservation).await?.reached.is_empty() {
            Ok(DiscoverablePasskeyConfirmation::Invalid)
        } else {
            Ok(DiscoverablePasskeyConfirmation::RateLimited)
        }
    }

    async fn unidentified_discoverable_failure(
        &self,
        source_ip: Option<&str>,
    ) -> Result<DiscoverablePasskeyConfirmation, AuthFactorServiceError> {
        let dimensions = match (source_ip, self.missing_source_ip_policy) {
            (Some(source_ip), _) => vec![(FailureDimension::SourceIp, source_ip.to_owned())],
            (None, MissingSourceIpPolicy::Skip) => {
                tracing::warn!(
                    event = "auth_limiter.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Skip.as_str(),
                    "unidentified discoverable Passkey failure cannot be rate limited"
                );
                return Ok(DiscoverablePasskeyConfirmation::Invalid);
            }
            (None, MissingSourceIpPolicy::Reject) => {
                return Err(AuthFactorServiceError::SourceIpUnavailable);
            }
        };
        let Some(reservation) = self.ensure_dimensions_allowed(dimensions.clone()).await? else {
            return Ok(DiscoverablePasskeyConfirmation::RateLimited);
        };
        self.discoverable_failure(reservation).await
    }

    async fn restore_discoverable_passkey(
        &self,
        key: &str,
        pending: &PendingDiscoverablePasskeyAuthentication,
    ) -> Result<(), AuthFactorServiceError> {
        let ttl = (pending.expires_at - self.clock.now()).whole_seconds();
        if ttl > 0 {
            self.tickets
                .save_json_if_absent(key, pending, ttl as u64)
                .await?;
        }
        Ok(())
    }

    async fn restore_discoverable_after_error(
        &self,
        key: &str,
        pending: &PendingDiscoverablePasskeyAuthentication,
    ) {
        if let Err(error) = self.restore_discoverable_passkey(key, pending).await {
            tracing::error!(
                error = %error,
                "failed to restore discoverable Passkey challenge after persistence error"
            );
        }
    }

    fn discoverable_passkey_key(&self, challenge_id: &str) -> String {
        self.tickets
            .namespaced(&format!("{DISCOVERABLE_PASSKEY_PREFIX}{challenge_id}"))
    }
}
