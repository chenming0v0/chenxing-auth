//! OAuth/OIDC Client registration and lifecycle boundaries.
//!
//! The service state, public result types, and error mapping stay here while
//! each use-case boundary is implemented by a focused child module. The
//! `ClientService` methods remain inherent methods, so their public paths are
//! unchanged.

use serde::Serialize;
use std::fmt;
use thiserror::Error;

use crate::{
    clients::domain::{ClientAuthMethod, ClientRegistrationError, ClientRegistrationLimits},
    oauth::refresh_store::RefreshTokenStore,
    plans::domain::AuthQuotaLimits,
};
use crate::{sqlx::PgPool, users::domain::UserId};

mod administration;
mod authentication;
mod lookup;
mod registration;
mod rotation;

// Keep the established public paths for request parsing and single-secret
// verification, even though the service implementation is split by use case.
pub use super::credentials::{ClientRegistrationRequest, verify_client_secret};

#[derive(Clone)]
pub struct ClientService {
    // Child use-case modules need the service dependencies, but callers outside
    // the clients module must not be able to construct or mutate them directly.
    pub(super) pool: PgPool,
    pub(super) limits: ClientRegistrationLimits,
    /// Refresh Token 存储，用于 Secret 轮换时清理已失效的凭据（Issue #62）。
    ///
    /// 用 `Option` 是为了让不依赖 Redis 的单元测试仍能构造 `ClientService`；
    /// 生产路径由 `AppState::new` 通过 `with_refresh_tokens` 注入。
    /// 为 `None` 时轮换会记 `tracing::error!`，避免静默退化成安全空操作。
    pub(super) refresh_tokens: Option<RefreshTokenStore>,
}

/// Successful Client authentication bound to the exact secret generation read
/// alongside the verified hash.
///
/// A bare `client_id` is not enough: secret rotation can commit after Argon2
/// verification but before a Refresh Token reaches Redis. Token issuance must
/// carry this snapshot to its persistence boundary instead of reading a newer
/// version and accidentally blessing an old secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedClient {
    client_id: String,
    client_secret_version: i64,
    allow_legacy_refresh_tokens: bool,
}

impl AuthenticatedClient {
    pub(super) fn new(
        client_id: String,
        client_secret_version: i64,
        allow_legacy_refresh_tokens: bool,
    ) -> Self {
        Self {
            client_id,
            client_secret_version,
            allow_legacy_refresh_tokens,
        }
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub const fn client_secret_version(&self) -> i64 {
        self.client_secret_version
    }

    pub const fn allows_legacy_refresh_tokens(&self) -> bool {
        self.allow_legacy_refresh_tokens
    }
}

pub struct RegisteredClientSecret {
    pub id: i64,
    pub client_id: String,
    /// 明文 secret；若为公开客户端（`auth_method = none`）则为 `None`。
    pub client_secret: Option<String>,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub auth_method: ClientAuthMethod,
}

impl fmt::Debug for RegisteredClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredClientSecret")
            .field("id", &self.id)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("client_name", &self.client_name)
            .field("redirect_uris", &self.redirect_uris)
            .field("scopes", &self.scopes)
            .field("auth_method", &self.auth_method)
            .finish()
    }
}

#[derive(Debug)]
pub struct RegisteredOwnedClient {
    pub client: RegisteredClientSecret,
    /// 创建事务实际用于准入的套餐配额，避免响应继续使用事务外旧快照。
    pub quota_limits: AuthQuotaLimits,
}

#[derive(Debug, Serialize)]
pub struct ClientSummary {
    pub id: i64,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub status: String,
    pub owner_user_id: Option<UserId>,
}

#[derive(Serialize)]
pub struct RotatedClientSecret {
    pub client_id: String,
    pub client_secret: String,
}

impl fmt::Debug for RotatedClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatedClientSecret")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum ClientServiceError {
    #[error(transparent)]
    Validation(#[from] ClientRegistrationError),
    #[error("could not hash client secret")]
    SecretHash,
    #[error("could not persist client")]
    Database(#[from] crate::sqlx::Error),
    #[error("normal user OAuth project quota has been exhausted")]
    QuotaExceeded,
    #[error("client data is invalid")]
    InvalidData,
    #[error("client secret was rotated by another concurrent request")]
    SecretRotationConflict,
}

impl ClientService {
    pub fn new(pool: PgPool) -> Self {
        Self::with_limits(pool, ClientRegistrationLimits::default())
    }

    pub fn with_limits(pool: PgPool, limits: ClientRegistrationLimits) -> Self {
        // 在服务开始接受请求前准备计时填充，避免首个失败认证多执行一次
        // dummy 哈希生成；请求期的校验仍全部在 spawn_blocking 中运行。
        super::credentials::prepare_dummy_client_secret_hash();
        Self {
            pool,
            limits,
            refresh_tokens: None,
        }
    }

    /// 注入 Refresh Token 存储（Issue #62：Secret 轮换后清理已失效的 token）。
    ///
    /// 建造者模式，返回 `Self` 支持链式调用。生产路径由 `AppState` 构造时注入。
    pub fn with_refresh_tokens(mut self, store: RefreshTokenStore) -> Self {
        self.refresh_tokens = Some(store);
        self
    }
}
