//! `linked_accounts` 表的持久化边界（Issue #706）。
//!
//! 本文件是该表的唯一 SQL 出口。所有语句显式写出、全部参数化绑定，禁止任何
//! 字符串拼接 SQL。并发一致性依赖迁移 0053 的两条唯一约束
//! （`linked_accounts_provider_uid_key`、`linked_accounts_provider_user_key`），
//! 插入冲突按约束名区分语义，不做 check-then-insert。
//!
//! 绑定 ID（`id` 列）是辰星生成的不透明字符串（`link_` 前缀 + 随机），解绑后
//! 不复用；uid 永久不可复用（`cltermux:<id>`），由唯一约束兜底。解绑是硬删
//! （DELETE 行），刷新类更新一律带 `binding_version` 条件，防止与并发解绑竞态：
//! 版本不匹配即视为绑定已消失，晚到的响应被上层丢弃。

use serde_json::Value;
use time::OffsetDateTime;

use crate::sqlx::{PgPool, PgRow, Row};
use crate::users::domain::UserId;

/// 绑定行 DTO，字段与迁移 0053 的表结构一一对应。
///
/// `snapshot_json` 只存经过校验的展示快照（协议上限 128 KiB，由表级 CHECK
/// 兜底）；凭据、令牌、密钥永不落库。
#[derive(Debug, Clone)]
pub struct LinkedAccountRow {
    pub id: String,
    pub user_id: UserId,
    pub provider_slug: String,
    pub kind: String,
    pub uid: String,
    pub subject: String,
    pub binding_version: i32,
    pub account_status: String,
    pub snapshot_json: Value,
    pub linked_at: OffsetDateTime,
    pub last_attempt_at: Option<OffsetDateTime>,
    pub last_success_at: Option<OffsetDateTime>,
    pub sync_status: String,
    pub sync_error: Option<String>,
}

impl<'r> crate::sqlx::FromRow<'r, PgRow> for LinkedAccountRow {
    fn from_row(row: &'r PgRow) -> Result<Self, crate::sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            provider_slug: row.try_get("provider_slug")?,
            kind: row.try_get("kind")?,
            uid: row.try_get("uid")?,
            subject: row.try_get("subject")?,
            binding_version: row.try_get("binding_version")?,
            account_status: row.try_get("account_status")?,
            snapshot_json: row
                .try_get::<crate::sqlx::types::Json<Value>, _>("snapshot_json")?
                .0,
            linked_at: row.try_get("linked_at")?,
            last_attempt_at: row.try_get("last_attempt_at")?,
            last_success_at: row.try_get("last_success_at")?,
            sync_status: row.try_get("sync_status")?,
            sync_error: row.try_get("sync_error")?,
        })
    }
}

/// 写入绑定行的错误分类。
///
/// 两个唯一约束分别对应协议里的两种冲突：
/// - [`StoreBindingError::UidTaken`]：该 provider 下 uid 已被占用（含同一用户
///   重复提交同一 uid 的幂等场景——上层用 `find_binding_by_uid` 复查归属后
///   决定返回既有绑定还是 409）。
/// - [`StoreBindingError::UserSlotTaken`]：该用户在此 provider 下的唯一槽位
///   已被另一个 uid 占用。
///
/// 两种错误都不得向客户端泄露占用者身份；归属判定只由上层用查询完成。
#[derive(Debug, thiserror::Error)]
pub enum StoreBindingError {
    #[error("uid is already bound on this provider")]
    UidTaken,
    #[error("user already has a binding on this provider")]
    UserSlotTaken,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("the browser session changed while binding the account")]
    SessionInvalid,
    #[error("the user account is disabled")]
    UserDisabled,
}

/// 判定数据库错误是否来自指定唯一约束。
///
/// 只看约束名而不解析错误文本：错误文本随 PostgreSQL 版本和 locale 变化，
/// 用它做判定等于把语义绑在数据库的措辞上（与 `src/admin/user_creation.rs`
/// 同一约定）。
fn unique_violation(error: &crate::sqlx::Error, constraint: &str) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.constraint())
        .is_some_and(|name| name == constraint)
}

/// `linked_accounts` 表的仓储实现，持有连接池。
#[derive(Clone)]
pub struct LinkedAccountRepository {
    pool: PgPool,
}

impl LinkedAccountRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 写入一条新绑定，返回落库后的完整行。
    ///
    /// 全字段参数化绑定；唯一冲突按约束名映射为
    /// [`StoreBindingError::UidTaken`] / [`StoreBindingError::UserSlotTaken`]。
    /// 幂等语义（同一用户重复提交同一 uid → 返回既有绑定）由上层在捕获
    /// `UidTaken` 后用 [`Self::find_binding_by_uid`] 复查归属实现，仓储不猜测。
    pub async fn insert_binding(
        &self,
        id: &str,
        user_id: UserId,
        provider_slug: &str,
        kind: &str,
        uid: &str,
        subject: &str,
        account_status: &str,
        snapshot_json: crate::sqlx::types::Json<Value>,
        linked_at: OffsetDateTime,
        last_attempt_at: Option<OffsetDateTime>,
        last_success_at: Option<OffsetDateTime>,
        sync_status: &str,
        sync_error: Option<&str>,
    ) -> Result<LinkedAccountRow, StoreBindingError> {
        let row = crate::sqlx::query_as::<_, LinkedAccountRow>(
            "INSERT INTO linked_accounts
                (id, user_id, provider_slug, kind, uid, subject,
                 account_status, snapshot_json, linked_at,
                 last_attempt_at, last_success_at, sync_status, sync_error)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING id, user_id, provider_slug, kind, uid, subject,
                 binding_version, account_status, snapshot_json, linked_at,
                 last_attempt_at, last_success_at, sync_status, sync_error",
        )
        .bind(id)
        .bind(user_id)
        .bind(provider_slug)
        .bind(kind)
        .bind(uid)
        .bind(subject)
        .bind(account_status)
        .bind(snapshot_json)
        .bind(linked_at)
        .bind(last_attempt_at)
        .bind(last_success_at)
        .bind(sync_status)
        .bind(sync_error)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| {
            if unique_violation(&error, "linked_accounts_provider_uid_key") {
                StoreBindingError::UidTaken
            } else if unique_violation(&error, "linked_accounts_provider_user_key") {
                StoreBindingError::UserSlotTaken
            } else {
                StoreBindingError::Database(error)
            }
        })?;
        Ok(row)
    }

    /// Insert after revalidating the exact browser session in the same transaction.
    /// The provider call happens before this method; no provider response can be
    /// committed after the session has been revoked or its epoch advanced.
    pub async fn insert_binding_for_session(
        &self,
        credential: crate::users::UserSessionCredential,
        id: &str,
        provider_slug: &str,
        kind: &str,
        uid: &str,
        subject: &str,
        account_status: &str,
        snapshot_json: crate::sqlx::types::Json<Value>,
        linked_at: OffsetDateTime,
    ) -> Result<LinkedAccountRow, StoreBindingError> {
        let mut transaction = self.pool.begin().await?;
        match crate::users::validate_user_session_in_transaction(&mut transaction, credential)
            .await?
        {
            crate::users::UserSessionValidation::Valid => {}
            crate::users::UserSessionValidation::SessionInvalid => {
                transaction.rollback().await?;
                return Err(StoreBindingError::SessionInvalid);
            }
            crate::users::UserSessionValidation::UserDisabled => {
                transaction.rollback().await?;
                return Err(StoreBindingError::UserDisabled);
            }
        }
        let result = crate::sqlx::query_as::<_, LinkedAccountRow>(
            "INSERT INTO linked_accounts
                (id, user_id, provider_slug, kind, uid, subject, account_status,
                 snapshot_json, linked_at, last_attempt_at, last_success_at, sync_status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $9, 'success')
             RETURNING id, user_id, provider_slug, kind, uid, subject, binding_version,
                 account_status, snapshot_json, linked_at, last_attempt_at, last_success_at,
                 sync_status, sync_error",
        )
        .bind(id)
        .bind(credential.user_id)
        .bind(provider_slug)
        .bind(kind)
        .bind(uid)
        .bind(subject)
        .bind(account_status)
        .bind(snapshot_json)
        .bind(linked_at)
        .fetch_one(&mut *transaction)
        .await;
        let row = result.map_err(|error| {
            if unique_violation(&error, "linked_accounts_provider_uid_key") {
                StoreBindingError::UidTaken
            } else if unique_violation(&error, "linked_accounts_provider_user_key") {
                StoreBindingError::UserSlotTaken
            } else {
                StoreBindingError::Database(error)
            }
        })?;
        transaction.commit().await?;
        Ok(row)
    }

    /// 按绑定 ID 查询本人绑定；不存在返回 `Ok(None)`（404 语义由上层定）。
    ///
    /// `user_id` 必须参与 WHERE：绑定 ID 虽不透明，但所有权判定不能只靠它，
    /// 否则任何持有历史 ID 的一方都能探测他人绑定。
    pub async fn find_binding_by_id(
        &self,
        id: &str,
        user_id: UserId,
    ) -> Result<Option<LinkedAccountRow>, crate::sqlx::Error> {
        crate::sqlx::query_as::<_, LinkedAccountRow>(
            "SELECT id, user_id, provider_slug, kind, uid, subject,
                    binding_version, account_status, snapshot_json, linked_at,
                    last_attempt_at, last_success_at, sync_status, sync_error
             FROM linked_accounts
             WHERE id = $1 AND user_id = $2",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
    }

    /// 查询用户在指定 provider 下的绑定（每 provider 至多一条，由唯一约束保证）。
    pub async fn find_binding_by_user_and_provider(
        &self,
        user_id: UserId,
        provider_slug: &str,
    ) -> Result<Option<LinkedAccountRow>, crate::sqlx::Error> {
        crate::sqlx::query_as::<_, LinkedAccountRow>(
            "SELECT id, user_id, provider_slug, kind, uid, subject,
                    binding_version, account_status, snapshot_json, linked_at,
                    last_attempt_at, last_success_at, sync_status, sync_error
             FROM linked_accounts
             WHERE user_id = $1 AND provider_slug = $2",
        )
        .bind(user_id)
        .bind(provider_slug)
        .fetch_optional(&self.pool)
        .await
    }

    /// 按 (provider, uid) 查询绑定，用于幂等判定与 resolve。
    ///
    /// 返回的行携带 `user_id`，上层据此区分"本人既有绑定（幂等返回）"与
    /// "他人占用（409 且不泄露占用者）"。
    pub async fn find_binding_by_uid(
        &self,
        provider_slug: &str,
        uid: &str,
    ) -> Result<Option<LinkedAccountRow>, crate::sqlx::Error> {
        crate::sqlx::query_as::<_, LinkedAccountRow>(
            "SELECT id, user_id, provider_slug, kind, uid, subject,
                    binding_version, account_status, snapshot_json, linked_at,
                    last_attempt_at, last_success_at, sync_status, sync_error
             FROM linked_accounts
             WHERE provider_slug = $1 AND uid = $2",
        )
        .bind(provider_slug)
        .bind(uid)
        .fetch_optional(&self.pool)
        .await
    }

    /// 列出用户全部绑定，按 `linked_at DESC, id DESC` 稳定排序。
    ///
    /// 绑定数量级小（每 provider 至多一条），不设分页上限；响应体积由上层控制。
    pub async fn list_bindings(
        &self,
        user_id: UserId,
    ) -> Result<Vec<LinkedAccountRow>, crate::sqlx::Error> {
        crate::sqlx::query_as::<_, LinkedAccountRow>(
            "SELECT id, user_id, provider_slug, kind, uid, subject,
                    binding_version, account_status, snapshot_json, linked_at,
                    last_attempt_at, last_success_at, sync_status, sync_error
             FROM linked_accounts
             WHERE user_id = $1
             ORDER BY linked_at DESC, id DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    /// 刷新成功路径：原子替换快照并推进版本号。
    ///
    /// `WHERE id = $1 AND binding_version = $2` 是防解绑竞态的关键：若绑定在
    /// 本次刷新期间被删除（或已被并发更新推进版本），条件不命中，返回
    /// `false`，上层丢弃晚到的供应商响应，绝不把快照写回已解绑的 ID 上。
    /// 命中时 `binding_version` 原子 +1，使其他在途的条件更新全部失效。
    ///
    /// 成功即清空 `sync_error`：`sync_status` 描述的是最近一次同步尝试的结果，
    /// 成功路径下历史失败信息不再有意义。
    pub async fn replace_snapshot_success(
        &self,
        id: &str,
        expected_binding_version: i32,
        snapshot: crate::sqlx::types::Json<Value>,
        account_status: &str,
        observed_at: OffsetDateTime,
    ) -> Result<bool, crate::sqlx::Error> {
        let updated = crate::sqlx::query(
            "UPDATE linked_accounts
             SET snapshot_json = $3,
                 account_status = $4,
                 sync_status = 'success',
                 sync_error = NULL,
                 last_attempt_at = $5,
                 last_success_at = $5,
                 binding_version = binding_version + 1
             WHERE id = $1 AND binding_version = $2",
        )
        .bind(id)
        .bind(expected_binding_version)
        .bind(snapshot)
        .bind(account_status)
        .bind(observed_at)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(updated == 1)
    }

    /// 记录一次刷新失败：只动尝试时间与失败描述，保留全部快照与成功时间。
    ///
    /// 同样带 `binding_version` 条件：解绑后到达的失败报告不得复活任何行。
    /// 推进版本号让并发的其他条件更新（成功路径、状态更新）失效，保证
    /// "最后一次写入者"由数据库顺序决定，而不是由网络到达顺序决定。
    pub async fn mark_sync_failure(
        &self,
        id: &str,
        expected_binding_version: i32,
        error_code: &str,
        observed_at: OffsetDateTime,
    ) -> Result<bool, crate::sqlx::Error> {
        let updated = crate::sqlx::query(
            "UPDATE linked_accounts
             SET last_attempt_at = $3,
                 sync_status = 'failed',
                 sync_error = $4,
                 binding_version = binding_version + 1
             WHERE id = $1 AND binding_version = $2",
        )
        .bind(id)
        .bind(expected_binding_version)
        .bind(observed_at)
        .bind(error_code)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(updated == 1)
    }

    /// Claim a manual refresh slot. The conditional version update serializes concurrent
    /// refreshes and makes the following provider response safe to apply.
    pub async fn claim_refresh(
        &self,
        id: &str,
        expected_binding_version: i32,
        attempted_at: OffsetDateTime,
    ) -> Result<bool, crate::sqlx::Error> {
        let updated = crate::sqlx::query(
            "UPDATE linked_accounts
             SET last_attempt_at = $3, binding_version = binding_version + 1
             WHERE id = $1 AND binding_version = $2",
        )
        .bind(id)
        .bind(expected_binding_version)
        .bind(attempted_at)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(updated == 1)
    }

    /// 记录供应商明确给出的账号事实（disabled / missing）。
    ///
    /// 这是成功查询得到的事实，不是同步失败：`sync_status` 保持成功语义
    /// （置 'success'、清空 `sync_error`），`last_success_at` 不动——它描述的
    /// 是"最近一次成功取回快照"的时间，而本次只更新了状态事实，没有新快照。
    /// 快照内容不动：状态与展示快照是两个独立维度，混写会让"账号被禁用"
    /// 伪装成"快照刷新"。
    pub async fn mark_account_fact(
        &self,
        id: &str,
        expected_binding_version: i32,
        account_status: &str,
        observed_at: OffsetDateTime,
    ) -> Result<bool, crate::sqlx::Error> {
        let updated = crate::sqlx::query(
            "UPDATE linked_accounts
             SET account_status = $3,
                 last_attempt_at = $4,
                 sync_status = 'success',
                 sync_error = NULL,
                 binding_version = binding_version + 1
             WHERE id = $1 AND binding_version = $2",
        )
        .bind(id)
        .bind(expected_binding_version)
        .bind(account_status)
        .bind(observed_at)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(updated == 1)
    }

    /// 硬删绑定行，返回是否删到（`false` = 不存在或不属于该用户，幂等）。
    ///
    /// 解绑后绑定 ID 与 uid 均不复用：ID 由应用生成且永不回收，uid 的不可
    /// 复用性由唯一约束在重新绑定时兜底拒绝。
    pub async fn delete_binding(
        &self,
        id: &str,
        user_id: UserId,
    ) -> Result<bool, crate::sqlx::Error> {
        let deleted =
            crate::sqlx::query("DELETE FROM linked_accounts WHERE id = $1 AND user_id = $2")
                .bind(id)
                .bind(user_id)
                .execute(&self.pool)
                .await?
                .rows_affected();
        Ok(deleted == 1)
    }
}
