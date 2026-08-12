//! 用户用例边界。
//!
//! 本文件只保留服务结构、错误类型和构造函数，用例实现按边界分到子模块：
//!
//! - [`registration`]：注册、Owner 引导与特权用户创建。
//! - [`authentication`]：登录校验与失败限流协作。
//! - [`profile`]：本人资料读取、显示名更新与改密。
//! - [`avatar`]：头像规范化与持久化。
//! - [`administration`]：管理侧列表、计数、角色与状态变更。
//!
//! 子模块里都是 `impl UserService` 的固有方法，对外仍然是
//! `crate::users::service::UserService` 上的同名方法，调用路径不变。

use std::sync::Arc;

use thiserror::Error;

use super::{credentials::prepare_dummy_password_hash, domain::RegistrationError, repository};
use crate::{
    auth_limiter::{AuthFailureLimiter, MissingSourceIpPolicy},
    sqlx::PgPool,
};

mod administration;
mod authentication;
mod avatar;
mod profile;
mod registration;

pub use avatar::AvatarServiceError;

#[derive(Clone)]
pub struct UserService {
    // 子模块的 impl 块需要读这些字段：可见性放到 `users` 及其后代，
    // 不对 crate 其他模块开放。
    pub(super) pool: PgPool,
    pub(super) limiter: Arc<dyn AuthFailureLimiter>,
    pub(super) missing_source_ip_policy: MissingSourceIpPolicy,
}

#[derive(Debug, Error)]
pub enum UserServiceError {
    #[error(transparent)]
    Validation(#[from] RegistrationError),
    #[error("could not hash password")]
    PasswordHash,
    #[error("could not persist user")]
    Database(#[from] crate::sqlx::Error),
    #[error("credentials are invalid")]
    InvalidCredentials,
    #[error("login input format is invalid")]
    InvalidLoginInput,
    #[error("authentication rate limit reached")]
    RateLimited,
    #[error("authentication limiter failed: {0}")]
    Limiter(#[from] crate::auth_limiter::domain::AuthLimiterError),
    #[error("trusted source IP is unavailable")]
    SourceIpUnavailable,
    #[error("last active owner is required")]
    LastOwnerRequired,
    /// 业务写入要求同事务审计，而审计写入失败，因此业务写入已回滚（Issue #304）。
    ///
    /// 对调用方的含义是「什么都没发生，可以重试」，与 [`Self::Database`] 区分开
    /// 只为让运维一眼看出该查审计表还是业务表。
    #[error("could not persist the audit record for this operation")]
    AuditUnavailable,
    #[error("owner bootstrap is required before public registration")]
    OwnerBootstrapRequired,
    #[error("email domain is not allowed by policy")]
    EmailDomainNotAllowed,
    #[error("email ownership verification is unavailable")]
    EmailVerificationUnavailable,
}

impl UserService {
    pub fn new(pool: PgPool, limiter: Arc<dyn AuthFailureLimiter>) -> Self {
        Self::with_source_ip_policy(pool, limiter, MissingSourceIpPolicy::Skip)
    }

    pub fn with_source_ip_policy(
        pool: PgPool,
        limiter: Arc<dyn AuthFailureLimiter>,
        missing_source_ip_policy: MissingSourceIpPolicy,
    ) -> Self {
        // 同步预热哑哈希（约 50 ms 的 Argon2）。这里刻意保持同步：构造发生在
        // 监听端口之前、任何请求到达之前，不占用服务期的 worker，同时让首个
        // 登录请求就具备等时的"用户不存在"路径（Issue #124）。
        prepare_dummy_password_hash();
        Self {
            pool,
            limiter,
            missing_source_ip_policy,
        }
    }
}

#[derive(Debug)]
pub enum BootstrapOwnerResult {
    Created(repository::UserProfile),
    AlreadyConfigured,
    RequiresEmptyDatabase,
}
