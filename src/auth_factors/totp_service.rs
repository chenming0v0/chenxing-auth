use super::{AuthFactorService, AuthFactorServiceError};
use crate::{
    auth_factors::{
        crypto::{DecryptedTotpSecret, encrypt_totp_secret_with_ring},
        repository,
    },
    auth_limiter::{FailureDimension, LimiterDimension, MissingSourceIpPolicy},
    users::domain::UserId,
};

impl AuthFactorService {
    pub(super) async fn account_key(
        &self,
        user_id: UserId,
    ) -> Result<String, AuthFactorServiceError> {
        repository::find_user_email(&self.pool, user_id)
            .await?
            .ok_or(AuthFactorServiceError::UserNotFound)
    }

    pub(super) fn failure_dimensions(
        &self,
        account_key: &str,
        ticket_id: Option<&str>,
        source_ip: Option<&str>,
    ) -> Result<Vec<LimiterDimension>, AuthFactorServiceError> {
        let mut dimensions = vec![(FailureDimension::Account, account_key.to_owned())];
        if let Some(ticket_id) = ticket_id {
            dimensions.push((FailureDimension::Ticket, ticket_id.to_owned()));
        }
        match (source_ip, self.missing_source_ip_policy) {
            (Some(source_ip), _) => {
                dimensions.push((FailureDimension::SourceIp, source_ip.to_owned()))
            }
            (None, MissingSourceIpPolicy::Skip) => tracing::warn!(
                event = "auth_limiter.source_ip_unavailable",
                policy = MissingSourceIpPolicy::Skip.as_str(),
                "authentication factor attempt is using non-IP dimensions"
            ),
            (None, MissingSourceIpPolicy::Reject) => {
                tracing::error!(
                    event = "auth_limiter.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Reject.as_str(),
                    "authentication factor attempt rejected without trusted ConnectInfo"
                );
                return Err(AuthFactorServiceError::SourceIpUnavailable);
            }
        }
        Ok(dimensions)
    }

    pub(super) async fn ensure_dimensions_allowed(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<bool, AuthFactorServiceError> {
        Ok(!self.limiter.reserve(dimensions).await?)
    }

    pub(super) async fn record_failure(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<crate::auth_limiter::domain::FailureRecord, AuthFactorServiceError> {
        Ok(self.limiter.record_reserved_failures(dimensions).await?)
    }

    pub(super) async fn release_dimensions(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<(), AuthFactorServiceError> {
        Ok(self.limiter.release(dimensions).await?)
    }

    pub(super) async fn claim_totp_timestep(
        &self,
        user_id: UserId,
        timestep: u64,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<bool, AuthFactorServiceError> {
        let claimed = match self.tickets.claim_totp_timestep(user_id, timestep).await {
            Ok(claimed) => claimed,
            Err(error) => {
                self.release_dimensions(dimensions).await?;
                return Err(error.into());
            }
        };
        self.release_dimensions(dimensions).await?;
        Ok(claimed)
    }

    pub(super) async fn invalidate_ticket(
        &self,
        ticket_id: &str,
    ) -> Result<(), AuthFactorServiceError> {
        self.tickets.take(ticket_id).await?;
        self.tickets
            .delete(&Self::totp_setup_key(ticket_id))
            .await?;
        Ok(())
    }

    pub(super) fn totp_setup_key(ticket_id: &str) -> String {
        format!("{}{}", super::TOTP_SETUP_PREFIX, ticket_id)
    }

    pub(super) async fn reencrypt_totp_secret_if_needed(
        &self,
        user_id: UserId,
        current_ciphertext: &[u8],
        decrypted: &DecryptedTotpSecret,
    ) -> Result<(), AuthFactorServiceError> {
        if !decrypted.needs_reencryption {
            return Ok(());
        }
        let replacement =
            encrypt_totp_secret_with_ring(&self.encryption_keys, &decrypted.plaintext)?;
        repository::update_totp_factor_if_current(
            &self.pool,
            user_id,
            current_ciphertext,
            &replacement,
        )
        .await?;
        Ok(())
    }
}
