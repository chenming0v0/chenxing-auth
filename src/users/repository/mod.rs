//! 用户仓储边界。
//!
//! 本文件只保留跨子模块共享的行类型，具体 SQL 按职责分到子模块：
//!
//! - [`lookup`]：读取路径（凭据、资料、列表）。
//! - [`write`]：写入路径（插入、资料更新、改密）。
//! - [`owner_bootstrap`]：Owner 引导与受 Owner 前提约束的创建。
//! - [`role_guard`]：角色与状态守卫（最后一个活跃 Owner 规则）。
//!
//! 全部子模块条目在此 `pub use`，`crate::users::repository::*` 的既有引用路径不变。

use std::fmt;
use time::OffsetDateTime;

use super::domain::{UserId, UserRole, UserStatus};

mod lookup;
mod owner_bootstrap;
mod role_guard;
mod write;

pub use lookup::{
    find_credentials_by_email, find_credentials_by_id, find_credentials_by_identifier,
    find_profile_by_id, list_users,
};
pub use owner_bootstrap::{
    BootstrapOwnerOutcome, bootstrap_owner, insert_user_after_owner, owner_exists,
};
pub use role_guard::{SetRoleOutcome, set_user_role, set_user_status, set_user_status_guarded};
pub use write::{
    change_password_and_revoke_all, insert_user, insert_user_in_transaction, update_display_name,
};

/// 刚写入的用户行。
///
/// `role` 与 `status` 是插入时实际落库的值而不是调用方的猜测：服务层据此构造
/// `PublicUser`，不再在响应里重复写一遍 `"active"` / `UserRole::User` 字面量。
pub struct NewUser {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub role: UserRole,
    pub status: UserStatus,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for NewUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewUser")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password_hash", &"<redacted>")
            .field("display_name", &self.display_name)
            .field("role", &self.role)
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .finish()
    }
}

pub struct UserCredentials {
    pub id: UserId,
    pub email: String,
    pub password_hash: String,
    pub password_login_enabled: bool,
    pub status: String,
    pub role: UserRole,
}

impl fmt::Debug for UserCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserCredentials")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("password_hash", &"<redacted>")
            .field("password_login_enabled", &self.password_login_enabled)
            .field("status", &self.status)
            .field("role", &self.role)
            .finish()
    }
}

#[derive(Debug)]
pub struct UserProfile {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
    pub role: UserRole,
}

#[derive(Debug)]
pub struct UserPlanSummary {
    pub id: i64,
    pub code: String,
    pub name: String,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug)]
pub struct ListedUser {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
    pub role: UserRole,
    pub created_at: OffsetDateTime,
    pub plan: Option<UserPlanSummary>,
}
