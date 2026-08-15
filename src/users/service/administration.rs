//! 管理侧列表、计数、角色与状态变更。
//!
//! 角色与状态的"最后一个活跃 Owner"守卫在仓储层判定，这里只把仓储层的业务终局
//! 翻译成 `UserServiceError`（Issue #126 / #283），两条写路径共用同一张翻译表。

use super::{UserService, UserServiceError};
use crate::audit::AuditEvent;
use crate::users::{
    domain::{OwnerTargetAccess, UserId, UserRole, UserStatus},
    query_repository,
    repository::{self, OwnerGuardOutcome},
};

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
        access: OwnerTargetAccess,
    ) -> Result<bool, UserServiceError> {
        translate_owner_guard(repository::set_user_role(&self.pool, id, role, access).await?)
    }

    pub async fn set_role_with_audit(
        &self,
        id: UserId,
        role: UserRole,
        access: OwnerTargetAccess,
        audit_event: AuditEvent,
    ) -> Result<bool, UserServiceError> {
        let outcome = repository::set_user_role_with_audit(
            &self.pool,
            id,
            role,
            access,
            audit_event,
        )
        .await
        .map_err(|error| match error {
            repository::AuditedRoleGuardError::Database(error) => UserServiceError::Database(error),
            repository::AuditedRoleGuardError::Audit(error) => {
                tracing::error!(event = "user_role_update.audit_unavailable", error = %error);
                UserServiceError::AuditUnavailable
            }
        })?;
        translate_owner_guard(outcome)
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
        access: OwnerTargetAccess,
    ) -> Result<bool, UserServiceError> {
        translate_owner_guard(
            repository::set_user_status_guarded(&self.pool, id, status, access).await?,
        )
    }
}

/// Owner 守卫终局 → 服务层结果。角色与状态变更共用同一张翻译表。
fn translate_owner_guard(outcome: OwnerGuardOutcome) -> Result<bool, UserServiceError> {
    match outcome {
        OwnerGuardOutcome::Updated => Ok(true),
        OwnerGuardOutcome::NotFound => Ok(false),
        OwnerGuardOutcome::LastOwnerRequired => Err(UserServiceError::LastOwnerRequired),
        OwnerGuardOutcome::ManageRolesRequired => Err(UserServiceError::ManageRolesRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::translate_owner_guard;
    use crate::users::{repository::OwnerGuardOutcome, service::UserServiceError};

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
            Err(UserServiceError::LastOwnerRequired)
        ));
        assert!(matches!(
            translate_owner_guard(OwnerGuardOutcome::ManageRolesRequired),
            Err(UserServiceError::ManageRolesRequired)
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
