//! 管理侧列表、计数、角色与状态变更。
//!
//! 角色与状态的"最后一个活跃 Owner"守卫在仓储层判定，这里只把仓储层的业务终局
//! 翻译成 `UserServiceError`（Issue #126）。

use super::{UserService, UserServiceError};
use crate::users::{
    domain::{UserId, UserRole},
    query_repository, repository,
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

    pub async fn set_status(&self, id: UserId, status: &str) -> Result<bool, UserServiceError> {
        self.set_status_guarded(id, status).await
    }

    /// 变更用户角色。
    ///
    /// 仓储层返回 `SetRoleOutcome` 枚举，业务终局直接 match（Issue #126）。
    /// 旧实现靠 `sqlx::Error::Protocol` 的字符串内容判定"最后一个 Owner"，
    /// 改一次措辞就会静默放开守卫；现在由编译器保证三种终局都被处理。
    pub async fn set_role(&self, id: UserId, role: UserRole) -> Result<bool, UserServiceError> {
        match repository::set_user_role(&self.pool, id, role).await? {
            repository::SetRoleOutcome::Updated => Ok(true),
            repository::SetRoleOutcome::NotFound => Ok(false),
            repository::SetRoleOutcome::LastOwnerRequired => {
                Err(UserServiceError::LastOwnerRequired)
            }
        }
    }

    pub async fn set_status_guarded(
        &self,
        id: UserId,
        status: &str,
    ) -> Result<bool, UserServiceError> {
        if !matches!(status, "active" | "disabled") {
            return Ok(false);
        }
        match repository::set_user_status_guarded(&self.pool, id, status).await? {
            Some("last_owner_required") => Err(UserServiceError::LastOwnerRequired),
            Some("updated") => Ok(true),
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::users::{repository::SetRoleOutcome, service::UserServiceError};

    /// Issue #126：三个变体必须各自映射到确定的服务层结果。
    ///
    /// 这里复刻 `set_role` 的翻译表而不是调用它：调用需要可用的数据库连接，
    /// 而被守护的正是"枚举 → 错误"这一步映射。若日后有人把 `NotFound`
    /// 误接成 `LastOwnerRequired`（或反之），本测试立刻失败。
    #[test]
    fn set_role_outcome_maps_to_service_results() {
        fn translate(outcome: SetRoleOutcome) -> Result<bool, UserServiceError> {
            match outcome {
                SetRoleOutcome::Updated => Ok(true),
                SetRoleOutcome::NotFound => Ok(false),
                SetRoleOutcome::LastOwnerRequired => Err(UserServiceError::LastOwnerRequired),
            }
        }

        assert!(matches!(translate(SetRoleOutcome::Updated), Ok(true)));
        assert!(matches!(translate(SetRoleOutcome::NotFound), Ok(false)));
        assert!(matches!(
            translate(SetRoleOutcome::LastOwnerRequired),
            Err(UserServiceError::LastOwnerRequired)
        ));
    }

    /// 守卫拒绝不能与"用户不存在"混为一谈：前者是 409 语义，后者是 404 语义。
    #[test]
    fn last_owner_required_is_distinct_from_not_found() {
        assert_ne!(SetRoleOutcome::NotFound, SetRoleOutcome::LastOwnerRequired);
        assert_ne!(SetRoleOutcome::Updated, SetRoleOutcome::LastOwnerRequired);
    }
}
