//! 管理侧列表、计数、角色与状态变更。
//!
//! 角色与状态的"最后一个活跃 Owner"守卫在仓储层判定，这里只把仓储层的业务终局
//! 翻译成管理写专用的 [`ManagementWriteError`]（Issue #126 / #283 / #493），
//! 两条写路径共用同一张翻译表，不把并发授权终局泄漏到注册、登录等无关用例。

use super::{UserService, UserServiceError};
use crate::users::{
    ManagementActorCredential,
    domain::{UserId, UserRole, UserStatus},
    query_repository,
    repository::{self, OwnerGuardOutcome},
};

#[derive(Debug, thiserror::Error)]
pub enum ManagementWriteError {
    #[error("could not persist the management write")]
    Database(#[from] crate::sqlx::Error),
    #[error("last active owner is required")]
    LastOwnerRequired,
    #[error("managing an owner requires role management permission")]
    ManageRolesRequired,
    #[error("the management actor session is no longer valid")]
    ActorSessionInvalid,
    #[error("the management actor no longer has user management permission")]
    ActorPermissionRequired,
}

impl UserService {
    pub async fn list(&self) -> Result<Vec<repository::ListedUser>, UserServiceError> {
        Ok(repository::list_users(&self.pool).await?)
    }

    pub async fn query(
        &self,
        search: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<repository::ListedUser>, i64), UserServiceError> {
        Ok(query_repository::query_users(&self.pool, search, status, limit, offset).await?)
    }

    pub async fn counts(&self) -> Result<query_repository::UserCounts, UserServiceError> {
        Ok(query_repository::count_users(&self.pool).await?)
    }

    pub async fn list_administrators(
        &self,
    ) -> Result<Vec<repository::ListedUser>, UserServiceError> {
        Ok(query_repository::list_administrators(&self.pool).await?)
    }

    /// 变更用户角色。
    ///
    /// 仓储层返回 [`repository::OwnerGuardOutcome`]，业务终局直接 match（Issue #126）。
    /// 旧实现靠 `sqlx::Error::Protocol` 的字符串内容判定"最后一个 Owner"，
    /// 改一次措辞就会静默放开守卫；现在由编译器保证全部终局都被处理。
    pub async fn set_role(
        &self,
        id: UserId,
        role: UserRole,
        credential: ManagementActorCredential,
    ) -> Result<bool, ManagementWriteError> {
        translate_owner_guard(repository::set_user_role(&self.pool, id, role, credential).await?)
    }

    /// 变更用户状态。
    ///
    /// 入参是已解析的 [`UserStatus`]，所以 `Ok(false)` 只有一种含义：目标用户不存在。
    /// 旧实现同时用 `Ok(false)` 表示「状态串非法」，HTTP 层因此无法区分 400 与 404
    /// （Issue #283）；现在非法状态在类型上就到不了这里。
    pub async fn set_status_guarded(
        &self,
        id: UserId,
        status: UserStatus,
        credential: ManagementActorCredential,
    ) -> Result<bool, ManagementWriteError> {
        translate_owner_guard(
            repository::set_user_status_guarded(&self.pool, id, status, credential).await?,
        )
    }
}

/// Owner 守卫终局 → 服务层结果。角色与状态变更共用同一张翻译表。
fn translate_owner_guard(outcome: OwnerGuardOutcome) -> Result<bool, ManagementWriteError> {
    match outcome {
        OwnerGuardOutcome::Updated => Ok(true),
        OwnerGuardOutcome::NotFound => Ok(false),
        OwnerGuardOutcome::LastOwnerRequired => Err(ManagementWriteError::LastOwnerRequired),
        OwnerGuardOutcome::ManageRolesRequired => Err(ManagementWriteError::ManageRolesRequired),
        OwnerGuardOutcome::ActorSessionInvalid => Err(ManagementWriteError::ActorSessionInvalid),
        OwnerGuardOutcome::ActorPermissionRequired => {
            Err(ManagementWriteError::ActorPermissionRequired)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ManagementWriteError, translate_owner_guard};
    use crate::users::repository::OwnerGuardOutcome;

    /// Issue #126 / #283 / #323：每个变体必须映射到确定的服务层结果。
    ///
    /// 这里直接调用真正的翻译表（不再复刻）：`translate_owner_guard` 不接触数据库，
    /// 而被守护的正是"枚举 → 结果"这一步映射。若日后有人把 `NotFound` 误接成
    /// `LastOwnerRequired`（或反之），本测试立刻失败。
    #[test]
    fn owner_guard_outcome_maps_to_service_results() {
        assert!(matches!(
            translate_owner_guard(OwnerGuardOutcome::Updated),
            Ok(true)
        ));
        assert!(matches!(
            translate_owner_guard(OwnerGuardOutcome::NotFound),
            Ok(false)
        ));
        assert!(matches!(
            translate_owner_guard(OwnerGuardOutcome::LastOwnerRequired),
            Err(ManagementWriteError::LastOwnerRequired)
        ));
        assert!(matches!(
            translate_owner_guard(OwnerGuardOutcome::ManageRolesRequired),
            Err(ManagementWriteError::ManageRolesRequired)
        ));
        assert!(matches!(
            translate_owner_guard(OwnerGuardOutcome::ActorSessionInvalid),
            Err(ManagementWriteError::ActorSessionInvalid)
        ));
        assert!(matches!(
            translate_owner_guard(OwnerGuardOutcome::ActorPermissionRequired),
            Err(ManagementWriteError::ActorPermissionRequired)
        ));
    }

    /// 守卫拒绝不能与"用户不存在"混为一谈：前者是 409 语义，后者是 404 语义。
    #[test]
    fn last_owner_required_is_distinct_from_not_found() {
        assert_ne!(
            OwnerGuardOutcome::NotFound,
            OwnerGuardOutcome::LastOwnerRequired
        );
        assert_ne!(
            OwnerGuardOutcome::Updated,
            OwnerGuardOutcome::LastOwnerRequired
        );
    }
}
