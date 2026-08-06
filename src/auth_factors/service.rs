use std::sync::Arc;

use redis::Client;
use thiserror::Error;
use webauthn_rs::prelude::WebauthnError;

use crate::{
    auth_limiter::{AuthFailureLimiter, FailureDimension, MissingSourceIpPolicy},
    config::AuthEncryptionKeyRing,
    settings::{SettingsService, SettingsServiceError},
    sqlx::PgPool,
    users::domain::UserId,
};

use super::{
    crypto::SecretCryptoError,
    domain::{FactorMethod, LoginTicket, effective_factor_methods, setup_factor_methods},
    repository,
    store::{LoginTicketStore, LoginTicketStoreError},
};

#[path = "attempt_limiter.rs"]
mod attempt_limiter;
#[path = "passkey.rs"]
mod passkey;
#[path = "passkey_core.rs"]
mod passkey_core;
#[path = "totp_service.rs"]
mod totp_service;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpConfirmation {
    /// 待确认的 TOTP 注册不存在，调用方应回落到 `verify_totp_login`。
    /// 该变体只由 `confirm_totp_enrollment` 产生，`verify_totp_login` 永远不返回它。
    NoPendingEnrollment,
    InvalidTicket,
    InvalidCode,
    RateLimited,
    Completed(UserId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyConfirmation {
    InvalidTicket,
    InvalidCredential(UserId),
    RateLimited(UserId),
    Completed(UserId),
}

#[derive(Clone)]
pub struct AuthFactorService {
    pool: PgPool,
    tickets: LoginTicketStore,
    limiter: Arc<dyn AuthFailureLimiter>,
    missing_source_ip_policy: MissingSourceIpPolicy,
    encryption_keys: AuthEncryptionKeyRing,
    settings: SettingsService,
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
    #[error("passkey setting operation failed: {0}")]
    Settings(#[from] SettingsServiceError),
    #[error("passkey credential serialization failed: {0}")]
    PasskeySerialization(#[from] serde_json::Error),
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
        settings: SettingsService,
    ) -> Self {
        Self::new_with_source_ip_policy(
            pool,
            redis,
            limiter,
            encryption_keys,
            settings,
            MissingSourceIpPolicy::Skip,
        )
    }

    pub fn new_with_source_ip_policy(
        pool: PgPool,
        redis: Client,
        limiter: Arc<dyn AuthFailureLimiter>,
        encryption_keys: AuthEncryptionKeyRing,
        settings: SettingsService,
        missing_source_ip_policy: MissingSourceIpPolicy,
    ) -> Self {
        Self {
            tickets: LoginTicketStore::new_with_pool(redis, pool.clone()),
            pool,
            limiter,
            missing_source_ip_policy,
            encryption_keys,
            settings,
        }
    }

    pub async fn available_methods(
        &self,
        user_id: UserId,
    ) -> Result<Vec<FactorMethod>, AuthFactorServiceError> {
        let methods = repository::list_factor_methods(&self.pool, user_id).await?;
        let passkey_enabled = self.settings.passkey().await?.enabled;
        Ok(effective_factor_methods(methods, passkey_enabled))
    }

    pub async fn available_setup_methods(
        &self,
    ) -> Result<Vec<FactorMethod>, AuthFactorServiceError> {
        let passkey_enabled = self.settings.passkey().await?.enabled;
        Ok(setup_factor_methods(passkey_enabled))
    }

    pub async fn has_active_passkey_only_accounts(&self) -> Result<bool, AuthFactorServiceError> {
        Ok(repository::has_active_passkey_only_accounts(&self.pool).await?)
    }

    pub async fn is_passkey_recovery_required(
        &self,
        user_id: UserId,
    ) -> Result<bool, AuthFactorServiceError> {
        let methods = repository::list_factor_methods(&self.pool, user_id).await?;
        self.is_disabled_passkey_only(&methods).await
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

    async fn is_disabled_passkey_only(
        &self,
        methods: &[String],
    ) -> Result<bool, AuthFactorServiceError> {
        Ok(
            methods.len() == 1
                && methods[0] == "passkey"
                && !self.settings.passkey().await?.enabled,
        )
    }
}
