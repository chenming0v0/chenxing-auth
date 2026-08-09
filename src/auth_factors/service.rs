use std::sync::Arc;

use thiserror::Error;
use webauthn_rs::prelude::WebauthnError;

use crate::{
    auth_limiter::{AuthFailureLimiter, FailureDimension, MissingSourceIpPolicy},
    config::AuthEncryptionKeyRing,
    redis_client::RedisClient,
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
#[path = "recovery.rs"]
mod recovery;
#[path = "totp_service.rs"]
mod totp_service;

pub use recovery::{AccountFactorStatus, EncryptionKeyHealth, TotpFactorStatus, TotpResetOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpConfirmation {
    /// 待确认的 TOTP 注册不存在，调用方应回落到 `verify_totp_login`。
    /// 该变体只由 `confirm_totp_enrollment` 产生，`verify_totp_login` 永远不返回它。
    NoPendingEnrollment,
    InvalidTicket,
    InvalidCode,
    /// 密文引用的加密 kid 已不在 `AUTH_ENCRYPTION_KEYS` 内：服务端读不出种子，
    /// 与「用户输错验证码」是两件完全不同的事（#258）。重试无用，必须走管理端重置。
    KeyUnavailable,
    RateLimited,
    Completed(UserId),
}

/// 单个因子校验的三种真实结果。
///
/// 旧签名是 `Result<bool, _>`，把「码不对」和「服务端读不出种子」压成同一个 `false`，
/// 于是密钥退役后的锁死状态在日志、审计和 HTTP 响应里都伪装成一次普通的验证失败（#258）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorVerification {
    Accepted,
    Rejected,
    /// 加密 kid 已退役，密文不可解。不消耗失败额度，需要管理端重置因子。
    KeyUnavailable,
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
        redis: impl Into<RedisClient>,
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
        redis: impl Into<RedisClient>,
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
        holder_hash: &str,
    ) -> Result<(String, LoginTicket), AuthFactorServiceError> {
        let Some(session_epoch) = repository::find_session_epoch(&self.pool, user_id).await? else {
            return Err(AuthFactorServiceError::UserNotFound);
        };
        Ok(self
            .tickets
            .create_with_epoch_and_holder(user_id, methods, session_epoch, holder_hash.to_owned())
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
        holder_hash: &str,
    ) -> Result<Option<UserId>, AuthFactorServiceError> {
        Ok(self
            .tickets
            .find_for_holder(ticket_id, holder_hash)
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
