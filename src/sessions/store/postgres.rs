//! Postgres 权威记录路径（生产部署配置）。
//!
//! 会话元数据写进 `user_sessions` 表，载荷优先从库里取，库里找不到时回退到 Redis。
//! `find` 的 Redis 回退在行锁外执行（Issue #432）；`FOR UPDATE` 只包住 idle 续期写。
//! idle 判定用行上签发时写入的 `idle_timeout_seconds`（#644），不用 store 启动策略。
//! 撤销通过更新 `revoked_at` 列表达，并将撤销通知写进 `session_outbox`，由
//! outbox 处理器异步同步到 Redis。

use super::{SessionStore, SessionStoreError};
use crate::{
    sqlx::{Postgres, Transaction},
    users::domain::UserId,
};

#[path = "postgres_find.rs"]
mod find;
#[path = "postgres_lookup.rs"]
mod lookup;
#[path = "postgres_save.rs"]
mod save;

pub(super) use find::{find_authenticated_with_metadata, find_with_metadata_by_token_hash};
pub(super) use lookup::{list_for_user, revoke_for_user};
pub(super) use save::save_with_metadata;

/// A short PostgreSQL row lock that orders one OAuth token publication against Session logout.
pub(crate) struct SessionIssuanceGuard {
    transaction: crate::sqlx::Transaction<'static, crate::sqlx::Postgres>,
}

impl SessionIssuanceGuard {
    pub(crate) async fn release(self) -> Result<(), crate::sqlx::Error> {
        self.transaction.rollback().await
    }
}

/// Begin the shared user-generation fence used by token issuance (Issue #476).
///
/// `revoke_all_for_user_in_transaction` takes the same advisory lock before
/// advancing `users.session_epoch`. Taking it here first, then locking the
/// `users` row, is what makes an epoch bump conflict with issuance. A lockless
/// re-read, or `FOR SHARE OF sessions` alone, does not.
async fn begin_user_generation_fence(
    store: &SessionStore,
    user_id: UserId,
) -> Result<crate::sqlx::Transaction<'static, crate::sqlx::Postgres>, SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *transaction)
        .await?;
    crate::sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '5s'")
        .execute(&mut *transaction)
        .await?;
    lock_user_session_scope(&mut transaction, user_id).await?;
    Ok(transaction)
}

/// Final Session liveness and `session_epoch` fence (Issues #506 / #476).
///
/// `expected_epoch` is the generation already stamped on the Refresh Token.
/// It is compared under the user lock; this function must not re-read epoch
/// outside that lock.
pub(super) async fn acquire_issuance_guard(
    store: &SessionStore,
    session_id: i64,
    user_id: UserId,
    token_hash: &[u8],
    expected_epoch: i64,
) -> Result<Option<SessionIssuanceGuard>, SessionStoreError> {
    let mut transaction = begin_user_generation_fence(store, user_id).await?;
    let active: Option<bool> = crate::sqlx::query_scalar(
        "SELECT TRUE
         FROM user_sessions AS sessions
         JOIN users ON users.id = sessions.user_id
         WHERE sessions.id = $1
           AND sessions.token_hash = $2
           AND sessions.user_id = $3
           AND sessions.revoked_at IS NULL
           AND sessions.expires_at > NOW()
           AND sessions.last_seen_at > NOW() - MAKE_INTERVAL(secs => sessions.idle_timeout_seconds)
           AND sessions.session_epoch >= users.session_epoch
           AND users.status = 'active'
           AND users.session_epoch = $4
         FOR SHARE OF sessions, users",
    )
    .bind(session_id)
    .bind(token_hash)
    .bind(user_id)
    .bind(expected_epoch)
    .fetch_optional(&mut *transaction)
    .await?;
    if active.is_none() {
        transaction.rollback().await?;
        return Ok(None);
    }
    Ok(Some(SessionIssuanceGuard { transaction }))
}

/// Session-less `session_epoch` fence for Refresh Token rotation (Issue #476).
pub(super) async fn acquire_user_generation_guard(
    store: &SessionStore,
    user_id: UserId,
    expected_epoch: i64,
) -> Result<Option<SessionIssuanceGuard>, SessionStoreError> {
    let mut transaction = begin_user_generation_fence(store, user_id).await?;
    let current: Option<i64> = crate::sqlx::query_scalar(
        "SELECT session_epoch
         FROM users
         WHERE id = $1 AND status = 'active'
         FOR SHARE",
    )
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if current != Some(expected_epoch) {
        transaction.rollback().await?;
        return Ok(None);
    }
    Ok(Some(SessionIssuanceGuard { transaction }))
}

/// 按令牌哈希撤销单条会话。
///
/// `WHERE revoked_at IS NULL` 承担两件事。首先它保住原来 `COALESCE` 的语义：
/// 已撤销的行不被再次写入，首次撤销时刻不会被往后推，审计要的是第一次生效的时间。
/// 其次 `RETURNING` 把"这次调用是否真的改变了状态"变成可观察的事实——只有发生了
/// 未撤销到已撤销的转变，才有新的 Redis 投影需要删除。
///
/// Issue #275：这里原本无条件插入 outbox 事件。重复登出、并发登出、以及对不存在
/// 令牌的登出都会产生一个投递任务，而它要删的键早已不存在。这些事件必然"成功"，
/// 于是变成纯粹的表增长；在退出接口被反复调用的部署里，它们是 outbox 里的多数。
///
/// 撤销事件带上 `session_id`、`user_id` 和 `session_epoch`：这些字段在同一条
/// `RETURNING` 里就能拿到，让 dead-letter 行能被定位到具体用户和会话。投递逻辑
/// 对 `revoke_session` 只用 `token_hash`，因此附带字段不改变行为。
pub(super) async fn revoke_by_token_hash(
    store: &SessionStore,
    hash: &[u8],
) -> Result<(), SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let mut transaction = pool.begin().await?;
    let revoked: Option<(i64, UserId, i64)> = crate::sqlx::query_as(
        "UPDATE user_sessions
         SET revoked_at = NOW()
         WHERE token_hash = $1 AND revoked_at IS NULL
         RETURNING id, user_id, session_epoch",
    )
    .bind(hash)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some((session_id, user_id, session_epoch)) = revoked {
        crate::sqlx::query(
            "INSERT INTO session_outbox
                 (operation, session_id, user_id, token_hash, generation)
             VALUES ('revoke_session', $1, $2, $3, $4)",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(hash)
        .bind(session_epoch)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub(super) async fn revoke_all_for_user(
    store: &SessionStore,
    user_id: UserId,
) -> Result<(), SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let mut transaction = pool.begin().await?;
    if revoke_all_for_user_in_transaction(&mut transaction, user_id)
        .await?
        .is_none()
    {
        return Err(SessionStoreError::UserNotFound);
    }
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn lock_user_session_scope(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
) -> Result<(), crate::sqlx::Error> {
    crate::db::advisory_lock::lock_user(transaction, user_id).await
}

pub(crate) async fn revoke_all_for_user_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
) -> Result<Option<i64>, crate::sqlx::Error> {
    lock_user_session_scope(transaction, user_id).await?;
    let epoch: Option<i64> = crate::sqlx::query_scalar(
        "UPDATE users
         SET session_epoch = session_epoch + 1, updated_at = NOW()
         WHERE id = $1
         RETURNING session_epoch",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(epoch) = epoch else {
        return Ok(None);
    };

    crate::sqlx::query(
        "WITH revoked AS (
             UPDATE user_sessions
             SET revoked_at = COALESCE(revoked_at, NOW())
             WHERE user_id = $1 AND revoked_at IS NULL
             RETURNING id, user_id, token_hash
         )
         INSERT INTO session_outbox
             (operation, session_id, user_id, token_hash, generation)
         SELECT 'revoke_session', id, user_id, token_hash, $2
         FROM revoked",
    )
    .bind(user_id)
    .bind(epoch)
    .execute(&mut **transaction)
    .await?;
    crate::sqlx::query(
        "INSERT INTO session_outbox (operation, user_id, generation)
         VALUES ('revoke_user', $1, $2)",
    )
    .bind(user_id)
    .bind(epoch)
    .execute(&mut **transaction)
    .await?;
    Ok(Some(epoch))
}
