use std::sync::Arc;

use thiserror::Error;
use webauthn_rs::prelude::WebauthnError;

use crate::{
    auth_limiter::{AuthFailureLimiter, FailureDimension, MissingSourceIpPolicy},
    clock::SharedClock,
    config::AuthEncryptionKeyRing,
    redis_client::RedisClient,
    settings::{SettingsService, SettingsServiceError},
    sqlx::PgPool,
    users::domain::{AuthenticatedUser, UserId},
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
#[path = "totp_enrollment.rs"]
mod totp_enrollment;
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
    /// 携带 ticket 上记录的认证 epoch（Issue #274），供会话签发做原子版本校验。
    Completed(AuthenticatedUser),
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
    /// 携带 ticket 上记录的认证 epoch（Issue #274），供会话签发做原子版本校验。
    Completed(AuthenticatedUser),
}

#[derive(Clone)]
pub struct AuthFactorService {
    pool: PgPool,
    tickets: LoginTicketStore,
    limiter: Arc<dyn AuthFailureLimiter>,
    missing_source_ip_policy: MissingSourceIpPolicy,
    encryption_keys: AuthEncryptionKeyRing,
    settings: SettingsService,
    /// MFA 生命周期的时间来源：login ticket 的 5 分钟窗口和 TOTP 的当前 timestep。
    ///
    /// 失败计数窗口不用它——限流窗口一律取 Redis 的 `TIME`，见
    /// `auth_limiter::redis_scripts`。
    clock: SharedClock,
}

#[derive(Debug, Error)]
pub enum AuthFactorServiceError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("login ticket operation failed: {0}")]
    Ticket(#[from] LoginTicketStoreError),
    #[error("login ticket user was not found")]
    UserNotFound,
    /// 认证时读到的 `session_epoch` 已经被并发改密推进（Issue #274）。
    ///
    /// 调用方必须把它当成一次认证失败处理，不得回落成"用当前 epoch 重签"。
    #[error("authenticated session epoch is stale")]
    AuthenticationEpochChanged,
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
            clock: SharedClock::system(),
        }
    }

    /// 注入共享时钟，并让内部的 ticket store 使用同一个来源。
    ///
    /// 两者必须同源：ticket 的签发时刻由 store 决定，而有效期判定在 service，
    /// 各读一个时钟会让「刚签发的 ticket 已过期」这种自相矛盾成为可能。
    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.tickets = self.tickets.with_clock(clock.clone());
        self.clock = clock;
        self
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

    pub async fn has_passkeys(&self) -> Result<bool, AuthFactorServiceError> {
        Ok(repository::has_passkeys(&self.pool).await?)
    }

    pub async fn is_passkey_recovery_required(
        &self,
        user_id: UserId,
    ) -> Result<bool, AuthFactorServiceError> {
        let methods = repository::list_factor_methods(&self.pool, user_id).await?;
        self.is_disabled_passkey_only(&methods).await
    }

    /// 为一次已完成的第一因子认证签发 login ticket。
    ///
    /// ticket 上盖的是**认证时**的 epoch，不是创建时刻重新读到的当前值
    /// （Issue #274）。这条区别是修复的核心：重新读会把旧口令的认证结果套用到
    /// 并发改密之后的新 epoch 上，让一张本该失效的 ticket 通过后续所有 epoch 校验。
    ///
    /// 写入前先比对当前 epoch，是为了不把一张注定无效的 ticket 交给用户；
    /// 真正的安全保证来自两侧的版本校验：读取路径（`LoginTicketStore` 的
    /// epoch 比对）会拒绝任何 epoch 已漂移的 ticket，兑换路径的会话写入还会在
    /// 持锁事务内再确认一次。因此即使比对之后、Redis 写入之前发生改密，
    /// 那张 ticket 也只是一份不可用的字节，换不出任何有效凭据。
    pub async fn create_login_ticket(
        &self,
        authenticated: AuthenticatedUser,
        methods: Vec<FactorMethod>,
        holder_hash: &str,
    ) -> Result<(String, LoginTicket), AuthFactorServiceError> {
        let Some(current_epoch) =
            repository::find_session_epoch(&self.pool, authenticated.id).await?
        else {
            return Err(AuthFactorServiceError::UserNotFound);
        };
        if current_epoch != authenticated.session_epoch {
            tracing::warn!(
                event = "auth_factor.login_ticket.authentication_epoch_stale",
                user_id = authenticated.id,
                "login ticket issuance rejected because credentials were invalidated concurrently"
            );
            return Err(AuthFactorServiceError::AuthenticationEpochChanged);
        }
        Ok(self
            .tickets
            .create_with_epoch_and_holder(
                authenticated.id,
                methods,
                authenticated.session_epoch,
                holder_hash.to_owned(),
            )
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
