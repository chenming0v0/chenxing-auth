use std::sync::Arc;

use redis::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder, WebauthnError};

use crate::{
    auth_limiter::{AuthFailureLimiter, FailureDimension},
    config::AuthEncryptionKey,
    sqlx::PgPool,
    users::domain::UserId,
};

use super::{
    crypto::{SecretCryptoError, decrypt_totp_secret},
    domain::{FactorMethod, LoginTicket},
    persistence::persist_then_consume,
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
    encryption_key: AuthEncryptionKey,
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
}

impl AuthFactorService {
    pub fn new(
        pool: PgPool,
        redis: Client,
        limiter: Arc<dyn AuthFailureLimiter>,
        encryption_key: AuthEncryptionKey,
        rp_id: &str,
        origin: &str,
    ) -> Result<Self, WebauthnError> {
        let origin = url::Url::parse(origin).map_err(|_| WebauthnError::Configuration)?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)?.build()?;
        Ok(Self {
            pool,
            tickets: LoginTicketStore::new(redis),
            limiter,
            encryption_key,
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
        identifier: &str,
        source_ip: &str,
        code: &str,
    ) -> Result<bool, AuthFactorServiceError> {
        self.ensure_allowed(FailureDimension::Account, identifier)
            .await?;
        self.ensure_allowed(FailureDimension::SourceIp, source_ip)
            .await?;
        let Some(encrypted_secret) = repository::find_totp_secret(&self.pool, user_id).await?
        else {
            self.record_totp_failure(identifier, source_ip).await;
            return Ok(false);
        };
        let mut secret = decrypt_totp_secret(self.encryption_key.as_bytes(), &encrypted_secret)?;
        let valid = verify_totp_code_current(&secret, code);
        secret.fill(0);
        if !valid {
            self.record_totp_failure(identifier, source_ip).await;
            return Ok(false);
        }
        if let Err(error) = self
            .limiter
            .clear(FailureDimension::Account, identifier)
            .await
        {
            tracing::warn!(
                error = %error,
                dimension = FailureDimension::Account.as_str(),
                "authentication limiter unavailable; TOTP success did not clear account failures"
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
        let encrypted_secret = super::crypto::encrypt_totp_secret(
            self.encryption_key.as_bytes(),
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
        source_ip: &str,
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
        if self.ensure_ticket_allowed(ticket_id, source_ip).await {
            self.invalidate_ticket(ticket_id).await?;
            return Ok(TotpConfirmation::RateLimited);
        }
        let mut secret =
            decrypt_totp_secret(self.encryption_key.as_bytes(), &pending.encrypted_secret)?;
        let valid = verify_totp_code_current(&secret, code);
        secret.fill(0);
        if !valid {
            if self.record_ticket_failure(ticket_id, source_ip).await {
                self.invalidate_ticket(ticket_id).await?;
                return Ok(TotpConfirmation::RateLimited);
            }
            return Ok(TotpConfirmation::InvalidCode);
        }
        let confirmation = persist_then_consume(
            TotpConfirmation::Completed(ticket.user_id),
            TotpConfirmation::InvalidTicket,
            repository::insert_totp_factor(&self.pool, ticket.user_id, &pending.encrypted_secret),
            self.tickets.take(ticket_id),
        )
        .await?;
        self.tickets
            .delete(&Self::totp_setup_key(ticket_id))
            .await?;
        if let Err(error) = self
            .limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await
        {
            tracing::warn!(
                error = %error,
                dimension = FailureDimension::Ticket.as_str(),
                "authentication limiter unavailable; TOTP setup success did not clear ticket failures"
            );
        }
        Ok(confirmation)
    }

    pub async fn verify_totp_login(
        &self,
        ticket_id: &str,
        source_ip: &str,
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
        if self.ensure_ticket_allowed(ticket_id, source_ip).await {
            self.invalidate_ticket(ticket_id).await?;
            return Ok(TotpConfirmation::RateLimited);
        }
        let Some(encrypted_secret) =
            repository::find_totp_secret(&self.pool, ticket.user_id).await?
        else {
            if self.record_ticket_failure(ticket_id, source_ip).await {
                self.invalidate_ticket(ticket_id).await?;
                return Ok(TotpConfirmation::RateLimited);
            }
            return Ok(TotpConfirmation::InvalidTicket);
        };
        let mut secret = decrypt_totp_secret(self.encryption_key.as_bytes(), &encrypted_secret)?;
        let valid = verify_totp_code_current(&secret, code);
        secret.fill(0);
        if !valid {
            if self.record_ticket_failure(ticket_id, source_ip).await {
                self.invalidate_ticket(ticket_id).await?;
                return Ok(TotpConfirmation::RateLimited);
            }
            return Ok(TotpConfirmation::InvalidCode);
        }
        if self.tickets.take(ticket_id).await?.is_none() {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        if let Err(error) = self
            .limiter
            .clear(FailureDimension::Ticket, ticket_id)
            .await
        {
            tracing::warn!(
                error = %error,
                dimension = FailureDimension::Ticket.as_str(),
                "authentication limiter unavailable; TOTP success did not clear ticket failures"
            );
        }
        Ok(TotpConfirmation::Completed(ticket.user_id))
    }

    async fn ensure_allowed(
        &self,
        dimension: FailureDimension,
        value: &str,
    ) -> Result<(), AuthFactorServiceError> {
        match self.limiter.is_limited(dimension, value).await {
            Ok(true) => Err(AuthFactorServiceError::RateLimited),
            Ok(false) => Ok(()),
            Err(error) => {
                // The limiter is an abuse-control aid; Redis outage must not deny valid logins.
                tracing::warn!(
                    error = %error,
                    dimension = dimension.as_str(),
                    "authentication limiter unavailable; allowing TOTP attempt"
                );
                Ok(())
            }
        }
    }

    async fn ensure_ticket_allowed(&self, ticket_id: &str, source_ip: &str) -> bool {
        self.is_limited(FailureDimension::Ticket, ticket_id).await
            || self.is_limited(FailureDimension::SourceIp, source_ip).await
    }

    async fn record_ticket_failure(&self, ticket_id: &str, source_ip: &str) -> bool {
        let reached = self
            .record_limiter_failure(FailureDimension::Ticket, ticket_id)
            .await;
        self.record_limiter_failure(FailureDimension::SourceIp, source_ip)
            .await;
        reached
    }

    async fn record_totp_failure(&self, identifier: &str, source_ip: &str) {
        self.record_limiter_failure(FailureDimension::Account, identifier)
            .await;
        self.record_limiter_failure(FailureDimension::SourceIp, source_ip)
            .await;
    }

    async fn is_limited(&self, dimension: FailureDimension, value: &str) -> bool {
        match self.limiter.is_limited(dimension, value).await {
            Ok(limited) => limited,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    dimension = dimension.as_str(),
                    "authentication limiter unavailable; allowing TOTP attempt"
                );
                false
            }
        }
    }

    async fn record_limiter_failure(&self, dimension: FailureDimension, value: &str) -> bool {
        match self.limiter.record_failure(dimension, value).await {
            Ok(reached) => reached,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    dimension = dimension.as_str(),
                    "authentication limiter unavailable; TOTP failure was not recorded"
                );
                false
            }
        }
    }

    async fn invalidate_ticket(&self, ticket_id: &str) -> Result<(), AuthFactorServiceError> {
        self.tickets.take(ticket_id).await?;
        self.tickets
            .delete(&Self::totp_setup_key(ticket_id))
            .await?;
        Ok(())
    }

    fn totp_setup_key(ticket_id: &str) -> String {
        format!("{TOTP_SETUP_PREFIX}{ticket_id}")
    }
}
