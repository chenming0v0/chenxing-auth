//! OAuth/OIDC Client registration and lifecycle boundaries.
//!
//! The service state, public result types, and error mapping stay here while
//! each use-case boundary is implemented by a focused child module. The
//! `ClientService` methods remain inherent methods, so their public paths are
//! unchanged.

use serde::Serialize;
use std::fmt;
use thiserror::Error;

use crate::{sqlx::PgPool, users::domain::UserId};
use crate::{
    clients::domain::{ClientAuthMethod, ClientRegistrationError, ClientRegistrationLimits},
    oauth::refresh_store::RefreshTokenStore,
};

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
    /// Refresh Token 存储，用于 Secret 轮换时撤销已签发的凭据（Issue #62）。
    ///
    /// 用 `Option` 是为了让不依赖 Redis 的单元测试仍能构造 `ClientService`；
    /// 生产路径由 `AppState::new` 通过 `with_refresh_tokens` 注入。
    /// 为 `None` 时轮换会记 `tracing::error!`，避免静默退化成安全空操作。
    pub(super) refresh_tokens: Option<RefreshTokenStore>,
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

    /// 注入 Refresh Token 存储（Issue #62：Secret 轮换需要撤销已签发的 token）。
    ///
    /// 建造者模式，返回 `Self` 支持链式调用。生产路径由 `AppState` 构造时注入。
    pub fn with_refresh_tokens(mut self, store: RefreshTokenStore) -> Self {
        self.refresh_tokens = Some(store);
        self
    }
}
