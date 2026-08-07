//! Client administration: listing, metadata updates, and status changes.

use super::{ClientService, ClientServiceError, ClientSummary};
use crate::clients::{
    domain::{ClientRegistrationInput, validate_client_registration_with_limits},
    repository,
};
use crate::users::domain::UserId;

/// 管理端 Client 列表的默认与最大返回条数，与 User 列表保持一致。
const DEFAULT_CLIENT_LIST_LIMIT: i64 = 50;
const MAX_CLIENT_LIST_LIMIT: i64 = 200;

// 默认值必须落在上限内，否则 `normalize_list_limit` 的缺省分支会被 clamp 静默改写。
// 这是常量间的不变量，放在编译期断言里，改坏常量会直接编译失败。
const _: () = assert!(DEFAULT_CLIENT_LIST_LIMIT <= MAX_CLIENT_LIST_LIMIT);

/// 缺省取 `DEFAULT_CLIENT_LIST_LIMIT`，并夹到 `[1, MAX_CLIENT_LIST_LIMIT]`，
/// 避免非法值直接进入 SQL 的 LIMIT。
fn normalize_list_limit(limit: Option<i64>) -> i64 {
    limit
        .unwrap_or(DEFAULT_CLIENT_LIST_LIMIT)
        .clamp(1, MAX_CLIENT_LIST_LIMIT)
}

/// 缺省与负值都抬到 0，避免 SQL 的 OFFSET 收到负数报错。
fn normalize_list_offset(offset: Option<i64>) -> i64 {
    offset.unwrap_or(0).max(0)
}

impl ClientService {
    /// 列出 Client（管理端），支持分页。
    ///
    /// `limit` / `offset` 默认行为与 `AuditService::list` / `UserService::query` 保持一致，
    /// 避免无上限列表在单次响应里倾倒全表（Issue #67）。
    pub async fn list(
        &self,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<ClientSummary>, ClientServiceError> {
        let limit = normalize_list_limit(limit);
        let offset = normalize_list_offset(offset);
        Ok(repository::list_clients(&self.pool, None, limit, offset)
            .await?
            .into_iter()
            .map(to_summary)
            .collect())
    }

    pub async fn query(
        &self,
        search: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<ClientSummary>, i64), ClientServiceError> {
        let (clients, total) =
            repository::query_clients(&self.pool, search, status, limit, offset).await?;
        Ok((clients.into_iter().map(to_summary).collect(), total))
    }

    pub async fn count(&self) -> Result<i64, ClientServiceError> {
        Ok(repository::count_clients(&self.pool).await?)
    }

    /// 列出当前用户拥有的 Client。
    ///
    /// 尽管用户套餐的 `oauth_clients_limit` 通常较小，
    /// 仍用 `MAX_CLIENT_LIST_LIMIT` 作上限以避免静默截断。
    pub async fn list_for_user(
        &self,
        owner_user_id: UserId,
    ) -> Result<Vec<ClientSummary>, ClientServiceError> {
        Ok(
            repository::list_clients(&self.pool, Some(owner_user_id), MAX_CLIENT_LIST_LIMIT, 0)
                .await?
                .into_iter()
                .map(to_summary)
                .collect(),
        )
    }

    pub async fn update(
        &self,
        client_id: &str,
        input: ClientRegistrationInput,
    ) -> Result<bool, ClientServiceError> {
        let registration = validate_client_registration_with_limits(input, &self.limits)?;
        Ok(repository::update_client(
            &self.pool,
            None,
            client_id,
            &registration.client_name,
            &registration.redirect_uris,
            &registration.scopes,
        )
        .await?)
    }

    pub async fn update_for_user(
        &self,
        owner_user_id: UserId,
        client_id: &str,
        input: ClientRegistrationInput,
    ) -> Result<bool, ClientServiceError> {
        let registration = validate_client_registration_with_limits(input, &self.limits)?;
        Ok(repository::update_client(
            &self.pool,
            Some(owner_user_id),
            client_id,
            &registration.client_name,
            &registration.redirect_uris,
            &registration.scopes,
        )
        .await?)
    }

    pub async fn set_status(
        &self,
        client_id: &str,
        status: &str,
    ) -> Result<bool, ClientServiceError> {
        validate_status(status)?;
        Ok(repository::set_client_status(&self.pool, None, client_id, status).await?)
    }

    pub async fn set_status_for_user(
        &self,
        owner_user_id: UserId,
        client_id: &str,
        status: &str,
    ) -> Result<bool, ClientServiceError> {
        validate_status(status)?;
        Ok(
            repository::set_client_status(&self.pool, Some(owner_user_id), client_id, status)
                .await?,
        )
    }
}

fn to_summary(client: repository::ListedClient) -> ClientSummary {
    ClientSummary {
        id: client.id,
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        scopes: client.scopes,
        status: client.status,
        owner_user_id: client.owner_user_id,
    }
}

fn validate_status(status: &str) -> Result<(), ClientServiceError> {
    if matches!(status, "active" | "disabled") {
        Ok(())
    } else {
        Err(ClientServiceError::InvalidData)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 列表上限 clamp 逻辑独立于数据库（Issue #67）
    #[test]
    fn list_limit_clamps_to_max() {
        // 超过 MAX_CLIENT_LIST_LIMIT 被 clamp 到 200
        assert_eq!(normalize_list_limit(Some(i64::MAX)), MAX_CLIENT_LIST_LIMIT);
        // 小于 1（含负数）被 clamp 到 1，SQL 的 LIMIT 不会收到非法值
        assert_eq!(normalize_list_limit(Some(0)), 1);
        assert_eq!(normalize_list_limit(Some(-10)), 1);
        // 区间内的值原样透传
        assert_eq!(normalize_list_limit(Some(20)), 20);
    }

    #[test]
    fn default_list_limit_is_within_max() {
        assert_eq!(DEFAULT_CLIENT_LIST_LIMIT, 50);
        // 默认值与上限的关系由文件顶部的编译期断言保证，这里只验证缺省分支的取值。
        assert_eq!(normalize_list_limit(None), DEFAULT_CLIENT_LIST_LIMIT);
    }

    /// offset 负值被抬到 0，避免 SQL OFFSET 报错
    #[test]
    fn negative_offset_floors_to_zero() {
        assert_eq!(normalize_list_offset(Some(-5)), 0);
        assert_eq!(normalize_list_offset(Some(0)), 0);
        assert_eq!(normalize_list_offset(Some(120)), 120);
        // 不传 offset 时从头开始
        assert_eq!(normalize_list_offset(None), 0);
    }
}
