//! 同意记录的持久化层（基础设施层）
//!
//! 本模块是 `user_consents` 表的唯一 SQL 出口，并通过 [`ConsentRepository`]
//! trait 界定存储边界。
//!
//! **分层边界**（AGENTS.md：领域层和应用层不应依赖 SQL 查询细节）：
//! - trait 只暴露数据访问语义，不泄露 SQL 字符串或表结构。
//! - `PgConsentRepository` 是唯一的生产实现，持有 `PgPool`。
//! - 应用层（`service.rs`）泛型依赖 trait，单元测试可注入内存 mock。
//!
//! **返回值设计**：
//! `stored_scopes` 返回原始 scope 列表而不是「是否包含」的布尔判定，
//! 让 scope 覆盖规则留在领域层（`domain::scopes_are_covered`），
//! 而不是下沉成 SQL 条件。
//!
//! **状态版本号**（Issue #276）：
//! 写方法（`upsert_consent` / `soft_revoke`）返回本次跃迁产生的
//! `state_version`，读方法 `consent_state` 同时返回撤销标记和版本号。
//! Redis 缓存必须携带这个版本号，才能在写入交错时判定自己是否陈旧；
//! 缺少版本号的缓存值无法区分「我描述的是撤销后的状态」和
//! 「我描述的是撤销后又被重新授权前的状态」。

use std::future::Future;

use crate::sqlx::{PgPool, types::Json};
use crate::users::domain::UserId;
use time::OffsetDateTime;

use super::domain::{AuthorizedApp, ConsentState};

/// 同意记录的存储边界。
///
/// 所有方法只描述「读写什么」，不描述「怎么查」。返回的 Future 显式要求 `Send`，
/// 以便在 Axum handler（要求 `Send` future）中使用泛型 service。
pub trait ConsentRepository: Send + Sync {
    /// 读取用户对指定 client 已授予且未撤销的 scope 列表。
    ///
    /// 返回 `None` 表示不存在有效同意记录（从未授权，或已撤销）。
    fn stored_scopes(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<Vec<String>>, crate::sqlx::Error>> + Send;

    /// 插入或更新同意记录，清除撤销标记，并推进状态版本号。
    ///
    /// 返回 `None` 表示目标 client 不存在（调用方应映射为 `ClientNotFound`）；
    /// 返回 `Some(version)` 是本次重新授权产生的 `state_version`，
    /// 调用方据此写 Redis 缓存的条件更新。
    fn upsert_consent(
        &self,
        user_id: UserId,
        client_id: &str,
        scopes: &[String],
    ) -> impl Future<Output = Result<Option<i64>, crate::sqlx::Error>> + Send;

    /// 列出用户所有未撤销的授权应用。
    fn list_active_for_user(
        &self,
        user_id: UserId,
    ) -> impl Future<Output = Result<Vec<AuthorizedApp>, crate::sqlx::Error>> + Send;

    /// 软删除：标记同意为已撤销，并推进状态版本号。
    ///
    /// 返回 `None` 表示记录不存在或此前已撤销（幂等）；
    /// 返回 `Some(version)` 是本次撤销产生的 `state_version`。
    fn soft_revoke(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<i64>, crate::sqlx::Error>> + Send;

    /// 读取同意的撤销状态与状态版本号。
    ///
    /// 这是 Issue #64 的权威判定入口：Redis 缓存未命中时由此回源。
    /// 返回 `None` 表示不存在同意记录（从未授权）。
    fn consent_state(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<ConsentState>, crate::sqlx::Error>> + Send;
}

/// `ConsentRepository` 的 PostgreSQL 实现。
#[derive(Clone)]
pub struct PgConsentRepository {
    pool: PgPool,
}

impl PgConsentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ConsentRepository for PgConsentRepository {
    async fn stored_scopes(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<Vec<String>>, crate::sqlx::Error> {
        // 已撤销的记录（revoked_at IS NOT NULL）视同不存在，
        // 避免撤销后的 scope 仍被判定为有效授权。
        //
        // 这条查询同时是 Issue #276 的安全底线：即使 Redis 里存在一个「未撤销」
        // 的陈旧缓存标记，refresh / userinfo 仍要过这道 DB 判定，
        // 因此缓存永远只能拒绝请求，不能替数据库放行请求。
        let row = crate::sqlx::query_as::<_, (Json<Vec<String>>,)>(
            "SELECT c.scopes
             FROM user_consents c
             JOIN oauth_clients oc ON oc.id = c.client_id
             WHERE c.user_id = $1 AND oc.client_id = $2 AND c.revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(Json(scopes),)| scopes))
    }

    async fn upsert_consent(
        &self,
        user_id: UserId,
        client_id: &str,
        scopes: &[String],
    ) -> Result<Option<i64>, crate::sqlx::Error> {
        // 重新授权时必须把 revoked_at 清回 NULL：撤销状态的权威事实在数据库，
        // 若只清 Redis 缓存，回源查询会把用户刚刚重新授予的同意判定为已撤销。
        //
        // `state_version` 在同一条语句内自增并回传（Issue #276）：版本号与权威写入
        // 原子产生，调用方拿到的一定是「这次重新授权对应的那个版本」，
        // 不会因为另一个并发请求先提交而串号。
        let row = crate::sqlx::query_as::<_, (i64,)>(
            "INSERT INTO user_consents (user_id, client_id, scopes, updated_at, revoked_at, state_version)
             SELECT $1, id, $3, $4, NULL, 1 FROM oauth_clients WHERE client_id = $2
             ON CONFLICT (user_id, client_id) DO UPDATE
                 SET scopes        = CASE
                         WHEN user_consents.revoked_at IS NOT NULL THEN EXCLUDED.scopes
                         ELSE (
                             SELECT COALESCE(jsonb_agg(elem ORDER BY elem), '[]'::jsonb)
                             FROM (
                                 SELECT elem
                                 FROM jsonb_array_elements_text(user_consents.scopes) AS existing(elem)
                                 UNION
                                 SELECT elem
                                 FROM jsonb_array_elements_text(EXCLUDED.scopes) AS incoming(elem)
                             ) AS merged(elem)
                         )
                     END,
                     updated_at    = EXCLUDED.updated_at,
                     revoked_at    = NULL,
                     state_version = user_consents.state_version + 1
             RETURNING state_version",
        )
        .bind(user_id)
        .bind(client_id)
        .bind(serde_json::to_value(scopes).expect("scope list is serializable"))
        // 保留墙钟（Issue #299 的明确例外）：`updated_at` 只用于列表排序展示，
        // 授权是否有效由 `revoked_at IS NULL` 判定，与时间比较无关。
        .bind(OffsetDateTime::now_utc())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(version,)| version))
    }

    async fn list_active_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<AuthorizedApp>, crate::sqlx::Error> {
        // 软删除后的记录不再展示给用户：撤销事实保留在库中供审计，
        // 但「已授权应用」列表只包含当前生效的授权。
        let rows = crate::sqlx::query_as::<_, (String, String, Json<Vec<String>>, OffsetDateTime)>(
            "SELECT oc.client_id, oc.client_name, c.scopes, c.updated_at
             FROM user_consents c
             JOIN oauth_clients oc ON oc.id = c.client_id
             WHERE c.user_id = $1 AND c.revoked_at IS NULL
             ORDER BY c.updated_at DESC, oc.client_id ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(client_id, client_name, Json(scopes), updated_at)| AuthorizedApp {
                    client_id,
                    client_name,
                    scopes,
                    updated_at,
                },
            )
            .collect())
    }

    async fn soft_revoke(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<i64>, crate::sqlx::Error> {
        // 单条 UPDATE 即完成撤销，因此撤销在数据库层面天然原子（Issue #65）：
        // 不再需要「先写 Redis 再删 DB」的两步操作，也就没有中间分裂状态。
        //
        // `revoked_at IS NULL` 条件保证幂等：重复撤销不会刷新时间戳，
        // 首次撤销时刻作为审计证据保持稳定；也因此不会白白消耗版本号。
        //
        // `state_version` 与 `revoked_at` 在同一条 UPDATE 内推进并回传（Issue #276），
        // 调用方用它做 Redis 条件写，迟到的写入会被更高版本拒绝。
        let row = crate::sqlx::query_as::<_, (i64,)>(
            "UPDATE user_consents AS c
             SET revoked_at = $3,
                 state_version = c.state_version + 1
             FROM oauth_clients AS oc
             WHERE c.user_id = $1 AND c.client_id = oc.id AND oc.client_id = $2
               AND c.revoked_at IS NULL
             RETURNING c.state_version",
        )
        .bind(user_id)
        .bind(client_id)
        // 保留墙钟（Issue #299 的明确例外）：`revoked_at` 是撤销事实的时间戳，
        // 判定用的是它是否为 NULL，而不是与当前时间比较。
        .bind(OffsetDateTime::now_utc())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(version,)| version))
    }

    async fn consent_state(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<ConsentState>, crate::sqlx::Error> {
        let row = crate::sqlx::query_as::<_, (bool, i64)>(
            "SELECT c.revoked_at IS NOT NULL, c.state_version
             FROM user_consents c
             JOIN oauth_clients oc ON oc.id = c.client_id
             WHERE c.user_id = $1 AND oc.client_id = $2",
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        // 行不存在 = 从未授权。不存在的授权无法被撤销，也没有版本号可比较；
        // 真正的拦截由 `stored_scopes` 完成（无同意记录 → 无有效 scope → 拒绝）。
        Ok(row.map(|(revoked, version)| ConsentState::new(revoked, version)))
    }
}
