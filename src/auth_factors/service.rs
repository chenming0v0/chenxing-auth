use std::sync::Arc;

use redis::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder, WebauthnError};

use crate::{
    auth_limiter::{AuthFailureLimiter, FailureDimension, LimiterDimension, MissingSourceIpPolicy},
    config::AuthEncryptionKey,
    sqlx::PgPool,
    users::domain::UserId,
};

use super::{
    crypto::{SecretCryptoError, decrypt_totp_secret},
    domain::{FactorMethod, LoginTicket},
    persistence::consume_then_persist,
    repository,
    store::{LoginTicketStore, LoginTicketStoreError},
    totp::{TotpEnrollment, verify_totp_code_current_timestep},
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
    missing_source_ip_policy: MissingSourceIpPolicy,
    encryption_key: AuthEncryptionKey,
    webauthn: Webauthn,
}

#[derive(Debug, Error)]
pub enum AuthFactorServiceError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("login ticket operation failed: {0}")]
    Ticket(#[from] LoginTicketStoreError),
    #[error("login ticket user was not found")]
    UserNotFound,
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
    #[error("passkey authentication is disabled")]
    PasskeyDisabled,
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
        Self::new_with_source_ip_policy(
            pool,
            redis,
            limiter,
            encryption_key,
            rp_id,
            origin,
            MissingSourceIpPolicy::Skip,
        )
    }

    pub fn new_with_source_ip_policy(
        pool: PgPool,
        redis: Client,
        limiter: Arc<dyn AuthFailureLimiter>,
        encryption_key: AuthEncryptionKey,
        rp_id: &str,
        origin: &str,
        missing_source_ip_policy: MissingSourceIpPolicy,
    ) -> Result<Self, WebauthnError> {
        let origin = url::Url::parse(origin).map_err(|_| WebauthnError::Configuration)?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)?.build()?;
        let ticket_pool = pool.clone();
        Ok(Self {
            pool,
            tickets: LoginTicketStore::new_with_pool(redis, ticket_pool),
            limiter,
            missing_source_ip_policy,
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
        let Some(session_epoch) = repository::find_session_epoch(&self.pool, user_id).await? else {
            return Err(AuthFactorServiceError::UserNotFound);
        };
        Ok(self
            .tickets
            .create_with_epoch(user_id, methods, session_epoch)
            .await?)
    }

    pub async fn clear_account_failures(
        &self,
        user_id: UserId,
    ) -> Result<(), AuthFactorServiceError> {
        let account_key = self.account_key(user_id).await?;
        self.limiter
            .clear(FailureDimension::Account, &account_key)
            .await?;
        Ok(())
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
        let mut secret = match decrypt_totp_secret(self.encryption_key.as_bytes(), &encrypted_secret) {
            Ok(secret) => secret,
            Err(error) => {
                self.release_dimensions(dimensions).await?;
                return Err(error.into());
            }
        };
        let timestep = verify_totp_code_current_timestep(&secret, code);
        secret.fill(0);
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
        let account_key = self.account_key(ticket.user_id).await?;
        let dimensions = self.failure_dimensions(&account_key, Some(ticket_id), source_ip)?;
        if self.ensure_dimensions_allowed(dimensions.clone()).await? {
            return Ok(TotpConfirmation::RateLimited);
        }
        let mut secret = match decrypt_totp_secret(
            self.encryption_key.as_bytes(),
            &pending.encrypted_secret,
        ) {
            Ok(secret) => secret,
            Err(error) => {
                self.release_dimensions(dimensions).await?;
                return Err(error.into());
            }
        };
        let valid = verify_totp_code_current_timestep(&secret, code);
        secret.fill(0);
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
        let confirmation = consume_then_persist(
            TotpConfirmation::Completed(ticket.user_id),
            TotpConfirmation::InvalidTicket,
            self.tickets.take(ticket_id),
            repository::insert_totp_factor(&self.pool, ticket.user_id, &pending.encrypted_secret),
            |ticket| self.tickets.restore(ticket_id, ticket),
        )
        .await?;
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
        let encrypted_secret = match repository::find_totp_secret(&self.pool, ticket.user_id).await {
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
        let mut secret = match decrypt_totp_secret(self.encryption_key.as_bytes(), &encrypted_secret) {
            Ok(secret) => secret,
            Err(error) => {
                self.release_dimensions(dimensions).await?;
                return Err(error.into());
            }
        };
        let valid = verify_totp_code_current_timestep(&secret, code);
        secret.fill(0);
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
        if self.tickets.take(ticket_id).await?.is_none() {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        Ok(TotpConfirmation::Completed(ticket.user_id))
    }

    fn failure_dimensions(
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

    async fn ensure_dimensions_allowed(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<bool, AuthFactorServiceError> {
        Ok(!self.limiter.reserve(dimensions).await?)
    }

    async fn record_failure(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<crate::auth_limiter::domain::FailureRecord, AuthFactorServiceError> {
        Ok(self.limiter.record_reserved_failures(dimensions).await?)
    }

    async fn release_dimensions(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<(), AuthFactorServiceError> {
        Ok(self.limiter.release(dimensions).await?)
    }

    async fn account_key(&self, user_id: UserId) -> Result<String, AuthFactorServiceError> {
        repository::find_user_email(&self.pool, user_id)
            .await?
            .ok_or(AuthFactorServiceError::UserNotFound)
    }

    async fn claim_totp_timestep(
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
