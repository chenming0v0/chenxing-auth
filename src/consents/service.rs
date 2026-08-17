//! 同意用例服务（应用层）
//!
//! 编排同意相关的用例，通过 [`ConsentRepository`] trait 依赖存储，
//! 不持有 SQL 字符串，也不依赖 Axum 提取器或 Redis 客户端。
//!
//! **为什么引入 trait 而不是完全跟随 `clients` 模块**：
//! `clients` 的 service 直接调用 `repository::*` 自由函数并传 `&PgPool`，
//! 因此它的 service 层无法脱离 PostgreSQL 测试。Issue #91 的核心诉求正是
//! 「无法在不起 PostgreSQL 的情况下做单元测试」，AGENTS.md 也明确要求
//! 「使用 trait 定义必要的存储和服务边界，便于单元测试和替换实现」。
//! 所以这里保留 `clients` 的**文件结构**（domain / repository / service），
//! 但在存储边界上采用 trait —— 结构一致，可测性更强。
//!
//! **默认类型参数保证兼容**：
//! `ConsentService<R = PgConsentRepository>` 使外部 `ConsentService` 的写法
//! 与拆分前完全一致，`ConsentService::new(pool)` 签名不变。

use crate::sqlx::PgPool;
use crate::users::domain::UserId;

use super::{
    domain::{
        AuthorizedApp, ConsentServiceError, ConsentState, normalize_scopes, scopes_are_covered,
    },
    repository::{ConsentRepository, PgConsentRepository},
};

/// 同意用例入口。
///
/// 默认使用 PostgreSQL 实现；测试可注入实现了 [`ConsentRepository`] 的 mock。
#[derive(Clone)]
pub struct ConsentService<R = PgConsentRepository> {
    repository: R,
}

impl ConsentService<PgConsentRepository> {
    /// 生产构造器：签名与拆分前保持一致，`state.rs` 无需修改。
    pub fn new(pool: PgPool) -> Self {
        Self {
            repository: PgConsentRepository::new(pool),
        }
    }
}

impl<R: ConsentRepository> ConsentService<R> {
    /// 注入任意存储实现，供单元测试使用。
    pub fn with_repository(repository: R) -> Self {
        Self { repository }
    }

    /// 检查用户是否已对指定 client 授予请求的全部 scope。
    ///
    /// 已撤销的同意视同未授权（repository 侧过滤 `revoked_at IS NULL`）。
    pub async fn has_scopes(
        &self,
        user_id: UserId,
        client_id: &str,
        scopes: &[String],
    ) -> Result<bool, crate::sqlx::Error> {
        let Some(stored) = self.repository.stored_scopes(user_id, client_id).await? else {
            return Ok(false);
        };
        Ok(scopes_are_covered(&stored, scopes))
    }

    /// 保存（或更新）用户对某个 OAuth Client 的授权同意。
    ///
    /// 若用户此前撤销过该 client，本次保存会把 `revoked_at` 清回 NULL，
    /// 使撤销状态在权威存储侧解除（配合 `refresh_consent_cache` 同步 Redis 缓存）。
    ///
    /// 返回本次跃迁产生的 `state_version`（Issue #276）：调用方可以直接用它
    /// 做 Redis 条件写，不必再回查一次数据库。
    ///
    /// # 错误
    ///
    /// - `ClientNotFound`：指定的 `client_id` 在数据库中不存在
    /// - `Database`：数据库操作失败
    pub async fn save(
        &self,
        user_id: UserId,
        client_id: &str,
        scopes: &[String],
    ) -> Result<i64, ConsentServiceError> {
        let normalized = normalize_scopes(scopes);
        self.repository
            .upsert_consent(user_id, client_id, &normalized)
            .await?
            .ok_or(ConsentServiceError::ClientNotFound)
    }

    /// 列出用户当前生效的授权应用（不含已撤销）。
    pub async fn list_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<AuthorizedApp>, crate::sqlx::Error> {
        self.repository.list_active_for_user(user_id).await
    }

    /// 撤销用户对指定 client 的授权（软删除，写入 `revoked_at`）。
    ///
    /// 这是撤销的**权威且原子**写入（Issue #64 / #65）：单条 UPDATE 完成，
    /// 成功即代表撤销事实已持久化。调用方随后应 best-effort 失效 Redis 缓存，
    /// 缓存失败不影响正确性。
    ///
    /// 返回 `None` 表示无生效授权可撤销（不存在或已撤销），调用方可幂等返回 204；
    /// 返回 `Some(version)` 是本次撤销的 `state_version`，调用方必须把它带进
    /// Redis 条件写，否则迟到的缓存写入会覆盖后续重新授权的正确状态（Issue #276）。
    pub async fn revoke_for_user(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<i64>, crate::sqlx::Error> {
        self.repository.soft_revoke(user_id, client_id).await
    }

    /// 查询撤销状态与状态版本号的权威判定（DB 回源路径）。
    ///
    /// 供 `TokenRevocationStore::is_consent_revoked` 在 Redis 缓存未命中时调用，
    /// 不应在热路径上绕过缓存直接调用。返回 `None` 表示从未授权。
    pub async fn consent_state(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<ConsentState>, crate::sqlx::Error> {
        self.repository.consent_state(user_id, client_id).await
    }

    /// 一次读取同意行的撤销状态、版本号和 scope 集合。
    ///
    /// 兑换闸门用它同时拿到 scope 覆盖判定所需的集合和 persist 后复核所需的
    /// `state_version`（Issue #475）。不要拆成 `consent_state` + `has_scopes`：
    /// 那是两次查询，版本号不再描述那次 scope 判定看到的行。
    pub async fn consent_grant(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<(ConsentState, Vec<String>)>, crate::sqlx::Error> {
        self.repository.consent_grant(user_id, client_id).await
    }

    /// 撤销状态的布尔视图。
    ///
    /// 「不存在同意记录」判定为未撤销：不存在的授权无法被撤销，
    /// 真正的拦截由 `has_scopes` 完成。
    pub async fn is_revoked(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<bool, crate::sqlx::Error> {
        Ok(self
            .consent_state(user_id, client_id)
            .await?
            .is_some_and(|state| state.revoked))
    }
}
