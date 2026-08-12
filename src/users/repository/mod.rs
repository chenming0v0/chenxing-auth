//! 用户仓储边界。
//!
//! 本文件只保留跨子模块共享的行类型，具体 SQL 按职责分到子模块：
//!
//! - [`lookup`]：读取路径（凭据、资料、列表）。
//! - [`write`]：写入路径（插入、资料更新、改密）。
//! - [`avatar`]：头像字节的读写与清除。
//! - [`owner_bootstrap`]：Owner 引导与受 Owner 前提约束的创建。
//! - [`role_guard`]：角色与状态守卫（最后一个活跃 Owner 规则）。
//!
//! 全部子模块条目在此 `pub use`，`crate::users::repository::*` 的既有引用路径不变。

use std::fmt;
use time::OffsetDateTime;

use super::domain::{UserId, UserRole, UserStatus};

mod avatar;
mod lookup;
mod owner_bootstrap;
mod role_guard;
mod write;

pub use avatar::{StoredAvatar, clear_avatar, find_avatar, update_avatar};
pub use lookup::{
    find_credentials_by_email, find_credentials_by_id, find_credentials_by_identifier,
    find_profile_by_id, list_users,
};
pub use owner_bootstrap::{
    BootstrapOwnerError, BootstrapOwnerOutcome, bootstrap_owner, insert_user_after_owner,
    owner_exists,
};
pub use role_guard::{OwnerGuardOutcome, set_user_role, set_user_status_guarded};
pub use write::{
    PasswordChangeOutcome, change_password_and_revoke_all, insert_user, insert_user_in_transaction,
    update_display_name,
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
    /// 与 `password_hash` 同一次读取取出的会话 epoch（Issue #274）。
    ///
    /// 口令校验通过后由 [`crate::users::domain::AuthenticatedUser`] 携带下去，
    /// 签发凭据前用它确认凭据版本未被并发改密推进。
    pub session_epoch: i64,
}

impl UserCredentials {
    /// 本次读取所对应的认证身份。
    ///
    /// 只在口令（或当前口令）校验通过后调用：它把"谁"和"依据哪个凭据版本"
    /// 打包在一起，避免调用方各自去猜 epoch 该从哪读。
    pub fn authenticated(&self) -> crate::users::domain::AuthenticatedUser {
        crate::users::domain::AuthenticatedUser::new(self.id, self.session_epoch)
    }
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
            .field("session_epoch", &self.session_epoch)
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
    /// 头像版本时间戳。`None` 表示没有头像，前端据此回落到首字母占位符；
    /// 有值时它同时充当头像 URL 的缓存击穿参数，因此不能省略进响应。
    pub avatar_updated_at: Option<OffsetDateTime>,
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

#[cfg(test)]
mod credentials_binding_tests {
    use super::UserCredentials;
    use crate::users::domain::UserRole;

    fn credentials(session_epoch: i64) -> UserCredentials {
        UserCredentials {
            id: 11,
            email: "user@example.test".to_owned(),
            password_hash: "argon2-hash".to_owned(),
            password_login_enabled: true,
            status: "active".to_owned(),
            role: UserRole::User,
            session_epoch,
        }
    }

    /// Issue #274：认证身份必须直接复用凭据行上的 `session_epoch`。
    ///
    /// 这是整条链路的起点：口令校验消费 `password_hash` 之后，唯一还能证明
    /// "校验依据的是哪个版本"的东西就是这个值。
    #[test]
    fn authenticated_identity_reuses_the_row_epoch() {
        let credentials = credentials(5);
        let authenticated = credentials.authenticated();

        assert_eq!(authenticated.id, credentials.id);
        assert_eq!(authenticated.session_epoch, 5);
    }

    /// 不同 epoch 的同一账号是两个不同的认证身份：比较必须包含 epoch，
    /// 否则调用方可以拿旧身份冒充新身份。
    #[test]
    fn authenticated_identities_differ_across_epochs() {
        assert_ne!(
            credentials(0).authenticated(),
            credentials(1).authenticated()
        );
        assert_eq!(
            credentials(2).authenticated(),
            credentials(2).authenticated()
        );
    }

    /// 凭据的 Debug 输出不得泄露哈希，但要保留 epoch 以便排查版本漂移。
    #[test]
    fn debug_output_redacts_the_hash_and_keeps_the_epoch() {
        let rendered = format!("{:?}", credentials(9));

        assert!(!rendered.contains("argon2-hash"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("session_epoch: 9"), "{rendered}");
    }
}
