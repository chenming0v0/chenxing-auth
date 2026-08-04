use std::sync::Arc;

use redis::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder, WebauthnError};

use crate::{
    auth_limiter::{AuthFailureLimiter, FailureDimension, MissingSourceIpPolicy},
    config::AuthEncryptionKeyRing,
    sqlx::PgPool,
    users::domain::UserId,
};

use super::{
    crypto::{SecretCryptoError, decrypt_totp_secret_with_ring, encrypt_totp_secret_with_ring},
    domain::{FactorMethod, LoginTicket},
    persistence::consume_then_persist,
    repository,
    store::{LoginTicketStore, LoginTicketStoreError},
    totp::{TotpEnrollment, verify_totp_code_current},
};

const TOTP_SETUP_PREFIX: &str = "chenxing:auth:totp-setup:";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingTotpSetup {
    user_id: UserId,
    encrypted_secret: Vec<u8>,
}

#[path = "passkey.rs"]
mod passkey;
#[path = "totp_service.rs"]
mod totp_service;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpConfirmation {
    InvalidTicket,
    InvalidCode,
    RateLimited,
    Completed(UserId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyConfirmation {
    InvalidTicket,
    InvalidCredential,
    Completed(UserId),
}

#[derive(Clone)]
pub struct AuthFactorService {
    pool: PgPool,
    tickets: LoginTicketStore,
    limiter: Arc<dyn AuthFailureLimiter>,
    missing_source_ip_policy: MissingSourceIpPolicy,
    encryption_keys: AuthEncryptionKeyRing,
    webauthn: Webauthn,
}

#[derive(Debug, Error)]
pub enum AuthFactorServiceError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("login ticket operation failed: {0}")]
    Ticket(#[from] LoginTicketStoreError),
    #[error("secret operation failed: {0}")]
    Secret(#[from] SecretCryptoError),
    #[error("authentication rate limit reached")]
    RateLimited,
    #[error("authentication limiter failed: {0}")]
    Limiter(#[from] crate::auth_limiter::domain::AuthLimiterError),
    #[error("TOTP enrollment operation failed: {0}")]
    Totp(#[from] totp_rs::TotpUrlError),
    #[error("WebAuthn operation failed: {0}")]
    Webauthn(#[from] WebauthnError),
    #[error("trusted source IP is unavailable")]
    SourceIpUnavailable,
    #[error("passkey credential conflicts with an existing credential")]
    PasskeyConflict,
    #[error("account already has an authentication factor")]
    FirstFactorAlreadyExists,
    #[error("passkey authentication is disabled")]
    PasskeyDisabled,
}

impl AuthFactorService {
    pub fn new(
        pool: PgPool,
        redis: Client,
        limiter: Arc<dyn AuthFailureLimiter>,
        encryption_keys: AuthEncryptionKeyRing,
        rp_id: &str,
        origin: &str,
    ) -> Result<Self, WebauthnError> {
        Self::new_with_source_ip_policy(
            pool,
            redis,
            limiter,
            encryption_keys,
            rp_id,
            origin,
            MissingSourceIpPolicy::Skip,
        )
    }

    pub fn new_with_source_ip_policy(
        pool: PgPool,
        redis: Client,
        limiter: Arc<dyn AuthFailureLimiter>,
        encryption_keys: AuthEncryptionKeyRing,
        rp_id: &str,
        origin: &str,
        missing_source_ip_policy: MissingSourceIpPolicy,
    ) -> Result<Self, WebauthnError> {
        let origin = url::Url::parse(origin).map_err(|_| WebauthnError::Configuration)?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)?.build()?;
        Ok(Self {
            pool,
            tickets: LoginTicketStore::new(redis),
            limiter,
            missing_source_ip_policy,
            encryption_keys,
            webauthn,
        })
    }

    pub async fn available_methods(
        &self,
        user_id: UserId,
    ) -> Result<Vec<FactorMethod>, AuthFactorServiceError> {
        let methods = repository::list_factor_methods(&self.pool, user_id).await?;
        Ok(methods
            .into_iter()
            .filter_map(|method| match method.as_str() {
                "totp" => Some(FactorMethod::Totp),
                "passkey" => Some(FactorMethod::Passkey),
                _ => None,
            })
            .collect())
    }

    pub async fn create_login_ticket(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
    ) -> Result<(String, LoginTicket), AuthFactorServiceError> {
        Ok(self.tickets.create(user_id, methods).await?)
    }

    pub async fn user_id_for_ticket(
        &self,
        ticket_id: &str,
    ) -> Result<Option<UserId>, AuthFactorServiceError> {
        Ok(self
            .tickets
            .find(ticket_id)
            .await?
            .map(|ticket| ticket.user_id))
    }

    pub async fn verify_totp(
        &self,
        user_id: UserId,
        _identifier: &str,
        source_ip: Option<&str>,
        code: &str,
    ) -> Result<bool, AuthFactorServiceError> {
        let account_key = user_id.to_string();
        let dimensions = self.failure_dimensions(&account_key, None, source_ip)?;
        self.ensure_dimensions_allowed(dimensions.clone()).await?;
        let Some(encrypted_secret) = repository::find_totp_secret(&self.pool, user_id).await?
        else {
            if !self.record_failure(dimensions).await?.reached.is_empty() {
                return Err(AuthFactorServiceError::RateLimited);
            }
            return Ok(false);
        };
        let decrypted = match decrypt_totp_secret_with_ring(&self.encryption_keys, &encrypted_secret) {
            Ok(value) => value,
            Err(SecretCryptoError::UnknownKeyId) => {
                tracing::warn!(
                    event = "auth_factor.totp.decrypt_key_unavailable",
                    "TOTP secret key is outside the configured retention window"
                );
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        let mut secret = decrypted.plaintext.clone();
        let valid = verify_totp_code_current(&secret, code);
        secret.fill(0);
        if !valid {
            if !self.record_failure(dimensions).await?.reached.is_empty() {
                return Err(AuthFactorServiceError::RateLimited);
            }
            return Ok(false);
        }
        self.limiter
            .clear(FailureDimension::Account, &account_key)
            .await?;
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
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Totp)
            || !repository::list_factor_methods(&self.pool, ticket.user_id)
                .await?
                .is_empty()
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
        let encrypted_secret = encrypt_totp_secret_with_ring(
            &self.encryption_keys,
            enrollment.secret_bytes(),
        )?;
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
        let account_key = ticket.user_id.to_string();
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Ok(TotpConfirmation::RateLimited);
        }
        let decrypted = match decrypt_totp_secret_with_ring(
            &self.encryption_keys,
            &pending.encrypted_secret,
        ) {
            Ok(value) => value,
            Err(SecretCryptoError::UnknownKeyId) => {
                tracing::warn!(
                    event = "auth_factor.totp.decrypt_key_unavailable",
                    "TOTP setup key is outside the configured retention window"
                );
                return Ok(TotpConfirmation::InvalidCode);
            }
            Err(error) => return Err(error.into()),
        };
        let mut secret = decrypted.plaintext.clone();
        let valid = verify_totp_code_current(&secret, code);
        secret.fill(0);
        if !valid {
            let record = self.record_failure(dimensions).await?;
            if record.reached(FailureDimension::Ticket) {
                self.invalidate_ticket(ticket_id).await?;
                return Ok(TotpConfirmation::RateLimited);
            }
            if !record.reached.is_empty() {
                return Ok(TotpConfirmation::RateLimited);
            }
            return Ok(TotpConfirmation::InvalidCode);
        }
        self.limiter
            .clear(FailureDimension::Account, &account_key)
            .await?;
        self.limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await?;
        let confirmation = match consume_then_persist(
            TotpConfirmation::Completed(ticket.user_id),
            TotpConfirmation::InvalidTicket,
            self.tickets.take(ticket_id),
            async {
                match repository::insert_totp_factor_if_empty(
                    &self.pool,
                    ticket.user_id,
                    &pending.encrypted_secret,
                )
                .await?
                {
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
        let account_key = ticket.user_id.to_string();
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Ok(TotpConfirmation::RateLimited);
        }
        let Some(encrypted_secret) =
            repository::find_totp_secret(&self.pool, ticket.user_id).await?
        else {
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
        let decrypted = match decrypt_totp_secret_with_ring(&self.encryption_keys, &encrypted_secret) {
            Ok(value) => value,
            Err(SecretCryptoError::UnknownKeyId) => {
                tracing::warn!(
                    event = "auth_factor.totp.decrypt_key_unavailable",
                    "TOTP secret key is outside the configured retention window"
                );
                return Ok(TotpConfirmation::InvalidCode);
            }
            Err(error) => return Err(error.into()),
        };
        let mut secret = decrypted.plaintext.clone();
        let valid = verify_totp_code_current(&secret, code);
        secret.fill(0);
        if !valid {
            let record = self.record_failure(dimensions).await?;
            if record.reached(FailureDimension::Ticket) {
                self.invalidate_ticket(ticket_id).await?;
                return Ok(TotpConfirmation::RateLimited);
            }
            if !record.reached.is_empty() {
                return Ok(TotpConfirmation::RateLimited);
            }
            return Ok(TotpConfirmation::InvalidCode);
        }
        self.limiter
            .clear(FailureDimension::Account, &account_key)
            .await?;
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

}
