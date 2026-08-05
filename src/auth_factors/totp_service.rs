use serde::{Deserialize, Serialize};

use super::{AuthFactorService, AuthFactorServiceError, TotpConfirmation};
use crate::{
    auth_factors::{
        crypto::{
            DecryptedTotpSecret, SecretCryptoError, decrypt_totp_secret_with_ring,
            encrypt_totp_secret_with_ring,
        },
        domain::{FactorMethod, LoginTicket},
        persistence::consume_then_persist,
        repository,
        totp::{TotpEnrollment, verify_totp_code_current_timestep},
    },
    auth_limiter::{FailureDimension, LimiterDimension, MissingSourceIpPolicy},
    users::domain::UserId,
};

const TOTP_SETUP_PREFIX: &str = "chenxing:auth:totp-setup:";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingTotpSetup {
    user_id: UserId,
    encrypted_secret: Vec<u8>,
}

impl AuthFactorService {
    pub async fn verify_totp(
        &self,
        user_id: UserId,
        _identifier: &str,
        source_ip: Option<&str>,
        code: &str,
    ) -> Result<bool, AuthFactorServiceError> {
        let account_key = self.account_key(user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, None, source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Err(AuthFactorServiceError::RateLimited);
        }
        let encrypted_secret = match repository::find_totp_secret(&self.pool, user_id).await {
            Ok(encrypted_secret) => encrypted_secret,
            Err(error) => {
                self.release_dimensions(dimensions).await?;
                return Err(error.into());
            }
        };
        let Some(encrypted_secret) = encrypted_secret else {
            if !self.record_failure(dimensions).await?.reached.is_empty() {
                return Err(AuthFactorServiceError::RateLimited);
            }
            return Ok(false);
        };
        let decrypted =
            match decrypt_totp_secret_with_ring(&self.encryption_keys, &encrypted_secret) {
                Ok(value) => value,
                Err(SecretCryptoError::UnknownKeyId) => {
                    self.release_dimensions(dimensions).await?;
                    tracing::warn!(
                        event = "auth_factor.totp.decrypt_key_unavailable",
                        "TOTP secret key is outside the configured retention window"
                    );
                    return Ok(false);
                }
                Err(error) => {
                    self.release_dimensions(dimensions).await?;
                    return Err(error.into());
                }
            };
        // 直接借用 decrypted.plaintext：它是 Zeroizing<Vec<u8>>，drop 时自动清零。
        // 旧写法 clone + fill(0) 只擦除了克隆副本，原始明文缓冲区反而活得更久
        // （后面还要传给 reencrypt_totp_secret_if_needed），等于没有真正擦除。
        let timestep = verify_totp_code_current_timestep(&decrypted.plaintext, code);
        let Some(timestep) = timestep else {
            if !self.record_failure(dimensions).await?.reached.is_empty() {
                return Err(AuthFactorServiceError::RateLimited);
            }
            return Ok(false);
        };
        if !self
            .claim_totp_timestep(user_id, timestep, dimensions)
            .await?
        {
            return Ok(false);
        }
        if let Err(error) = self
            .reencrypt_totp_secret_if_needed(user_id, &encrypted_secret, &decrypted)
            .await
        {
            tracing::warn!(
                event = "auth_factor.totp.lazy_reencryption_failed",
                error = %error,
                "TOTP verification succeeded but key rotation migration was deferred"
            );
        }
        Ok(true)
    }

    pub async fn start_totp_enrollment(
        &self,
        ticket_id: &str,
        account_name: &str,
        issuer: &str,
    ) -> Result<Option<TotpEnrollment>, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find(ticket_id).await? else {
            return Ok(None);
        };
        let factor_methods = repository::list_factor_methods(&self.pool, ticket.user_id).await?;
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Totp)
            || !self.can_start_totp_enrollment(&factor_methods).await?
        {
            return Ok(None);
        }
        if self
            .tickets
            .find_json::<PendingTotpSetup>(&Self::totp_setup_key(ticket_id))
            .await?
            .is_some()
        {
            return Ok(None);
        }
        let enrollment = TotpEnrollment::new(account_name, issuer)?;
        let encrypted_secret =
            encrypt_totp_secret_with_ring(&self.encryption_keys, enrollment.secret_bytes())?;
        self.tickets
            .save_json(
                &Self::totp_setup_key(ticket_id),
                &PendingTotpSetup {
                    user_id: ticket.user_id,
                    encrypted_secret,
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(Some(enrollment))
    }

    pub async fn confirm_totp_enrollment(
        &self,
        ticket_id: &str,
        source_ip: Option<&str>,
        code: &str,
    ) -> Result<TotpConfirmation, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find(ticket_id).await? else {
            return Ok(TotpConfirmation::InvalidTicket);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Totp)
        {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        let Some(pending) = self
            .tickets
            .find_json::<PendingTotpSetup>(&Self::totp_setup_key(ticket_id))
            .await?
        else {
            return Ok(TotpConfirmation::InvalidTicket);
        };
        let factor_methods = repository::list_factor_methods(&self.pool, ticket.user_id).await?;
        let passkey_recovery = self.is_disabled_passkey_only(&factor_methods).await?;
        let account_key = self.account_key(ticket.user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Ok(TotpConfirmation::RateLimited);
        }
        let decrypted =
            match decrypt_totp_secret_with_ring(&self.encryption_keys, &pending.encrypted_secret) {
                Ok(value) => value,
                Err(SecretCryptoError::UnknownKeyId) => {
                    self.release_dimensions(dimensions).await?;
                    tracing::warn!(
                        event = "auth_factor.totp.decrypt_key_unavailable",
                        "TOTP setup key is outside the configured retention window"
                    );
                    return Ok(TotpConfirmation::InvalidCode);
                }
                Err(error) => {
                    self.release_dimensions(dimensions).await?;
                    return Err(error.into());
                }
            };
        let valid = verify_totp_code_current_timestep(&decrypted.plaintext, code);
        let Some(_) = valid else {
            let record = self.record_failure(dimensions).await?;
            if record.reached(FailureDimension::Ticket) {
                self.invalidate_ticket(ticket_id).await?;
                return Ok(TotpConfirmation::RateLimited);
            }
            if !record.reached.is_empty() {
                return Ok(TotpConfirmation::RateLimited);
            }
            return Ok(TotpConfirmation::InvalidCode);
        };
        // The setup ticket is one-time; only login verification claims a replay timestep.
        self.release_dimensions(dimensions).await?;
        self.limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await?;
        let confirmation = match consume_then_persist(
            TotpConfirmation::Completed(ticket.user_id),
            TotpConfirmation::InvalidTicket,
            self.tickets.take(ticket_id),
            async {
                let result = if passkey_recovery {
                    repository::insert_totp_factor_for_passkey_recovery(
                        &self.pool,
                        ticket.user_id,
                        &pending.encrypted_secret,
                    )
                    .await?
                } else {
                    repository::insert_totp_factor_if_empty(
                        &self.pool,
                        ticket.user_id,
                        &pending.encrypted_secret,
                    )
                    .await?
                };
                match result {
                    repository::FirstFactorPersistenceResult::Stored => Ok(()),
                    repository::FirstFactorPersistenceResult::AlreadyExists => {
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
                let _ = self.tickets.take(ticket_id).await?;
                self.tickets
                    .delete(&Self::totp_setup_key(ticket_id))
                    .await?;
                return Ok(TotpConfirmation::InvalidTicket);
            }
            Err(error) => return Err(error),
        };
        self.tickets
            .delete(&Self::totp_setup_key(ticket_id))
            .await?;
        Ok(confirmation)
    }

    pub async fn verify_totp_login(
        &self,
        ticket_id: &str,
        source_ip: Option<&str>,
        code: &str,
    ) -> Result<TotpConfirmation, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find(ticket_id).await? else {
            return Ok(TotpConfirmation::InvalidTicket);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Totp)
        {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        let account_key = self.account_key(ticket.user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Ok(TotpConfirmation::RateLimited);
        }
        let encrypted_secret = match repository::find_totp_secret(&self.pool, ticket.user_id).await
        {
            Ok(encrypted_secret) => encrypted_secret,
            Err(error) => {
                self.release_dimensions(dimensions).await?;
                return Err(error.into());
            }
        };
        let Some(encrypted_secret) = encrypted_secret else {
            let record = self.record_failure(dimensions).await?;
            if record.reached(FailureDimension::Ticket) {
                self.invalidate_ticket(ticket_id).await?;
                return Ok(TotpConfirmation::RateLimited);
            }
            if !record.reached.is_empty() {
                return Ok(TotpConfirmation::RateLimited);
            }
            return Ok(TotpConfirmation::InvalidTicket);
        };
        let decrypted =
            match decrypt_totp_secret_with_ring(&self.encryption_keys, &encrypted_secret) {
                Ok(value) => value,
                Err(SecretCryptoError::UnknownKeyId) => {
                    self.release_dimensions(dimensions).await?;
                    tracing::warn!(
                        event = "auth_factor.totp.decrypt_key_unavailable",
                        "TOTP secret key is outside the configured retention window"
                    );
                    return Ok(TotpConfirmation::InvalidCode);
                }
                Err(error) => {
                    self.release_dimensions(dimensions).await?;
                    return Err(error.into());
                }
            };
        let valid = verify_totp_code_current_timestep(&decrypted.plaintext, code);
        let Some(timestep) = valid else {
            let record = self.record_failure(dimensions).await?;
            if record.reached(FailureDimension::Ticket) {
                self.invalidate_ticket(ticket_id).await?;
                return Ok(TotpConfirmation::RateLimited);
            }
            if !record.reached.is_empty() {
                return Ok(TotpConfirmation::RateLimited);
            }
            return Ok(TotpConfirmation::InvalidCode);
        };
        if !self
            .claim_totp_timestep(ticket.user_id, timestep, dimensions)
            .await?
        {
            return Ok(TotpConfirmation::InvalidCode);
        }
        self.limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await?;
        if let Err(error) = self
            .reencrypt_totp_secret_if_needed(ticket.user_id, &encrypted_secret, &decrypted)
            .await
        {
            tracing::warn!(
                event = "auth_factor.totp.lazy_reencryption_failed",
                error = %error,
                "TOTP verification succeeded but key rotation migration was deferred"
            );
        }
        if self.tickets.take(ticket_id).await?.is_none() {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        Ok(TotpConfirmation::Completed(ticket.user_id))
    }

    async fn can_start_totp_enrollment(
        &self,
        methods: &[String],
    ) -> Result<bool, AuthFactorServiceError> {
        if methods.is_empty() {
            return Ok(true);
        }
        self.is_disabled_passkey_only(methods).await
    }

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
        format!("{}{}", TOTP_SETUP_PREFIX, ticket_id)
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
