//! Postgres 权威记录路径（生产部署配置）。
//!
//! 会话元数据写进 `user_sessions` 表，载荷优先从库里取，库里找不到时回退到 Redis。
//! 撤销通过更新 `revoked_at` 列表达，并将撤销通知写进 `session_outbox`，由
//! outbox 处理器异步同步到 Redis。

use std::time::Duration;

use super::{SessionEpochBinding, SessionStore, SessionStoreError};
use crate::{
    sessions::domain::{Session, SessionPayload, session_token_hash_bytes},
    sqlx::{Postgres, Transaction},
    users::domain::{UserId, UserStatus},
};

#[path = "postgres_lookup.rs"]
mod lookup;

pub(super) use lookup::{
    find_with_metadata, find_with_metadata_by_token_hash, list_for_user, revoke_for_user,
};

/// 写入会话元数据。
///
/// `binding` 为 [`SessionEpochBinding::Authenticated`] 时，epoch 比对发生在本事务
/// 已经持有该用户的 advisory 锁与 `users` 行锁之后（Issue #274）。这一点是原子性的
/// 全部来源：改密走的 `revoke_all_for_user_in_transaction` 需要同一把 advisory 锁，
/// 因此两个事务只能串行——要么改密先提交、本次读到新 epoch 并拒绝写入，要么本次
/// 先提交、改密随后把这条会话一起撤销。不存在"读到旧 epoch 又按新 epoch 落库"的
/// 中间态。比对失败直接返回错误，事务连一行都没插入。
pub(super) async fn save_with_metadata(
    store: &SessionStore,
    session: &mut Session,
    _ttl: Duration,
    binding: SessionEpochBinding,
) -> Result<(), SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let user_id = session
        .user_id
        .parse::<UserId>()
        .map_err(|_| SessionStoreError::InvalidUserId)?;
    let token_hash = session_token_hash_bytes(&session.token).to_vec();
    let mut transaction = pool.begin().await?;
    lock_user_session_scope(&mut transaction, user_id).await?;
    let user_state: Option<(i64, String)> =
        crate::sqlx::query_as("SELECT session_epoch, status FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?;
    let Some((session_epoch, status)) = user_state else {
        return Err(SessionStoreError::UserNotFound);
    };
    if UserStatus::parse(&status) != Some(UserStatus::Active) {
        return Err(SessionStoreError::UserDisabled);
    }
    if let SessionEpochBinding::Authenticated(authenticated_epoch) = binding
        && authenticated_epoch != session_epoch
    {
        tracing::warn!(
            event = "session.authentication_epoch_stale",
            user_id,
            "session issuance rejected because credentials were invalidated concurrently"
        );
        return Err(SessionStoreError::AuthenticationEpochChanged);
    }
    let active_count: i64 = crate::sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM user_sessions
         WHERE user_id = $1
           AND revoked_at IS NULL
           AND expires_at > NOW()
           AND last_seen_at > NOW() - $2
           AND session_epoch >= $3",
    )
    .bind(user_id)
    .bind(store.idle_timeout_interval())
    .bind(session_epoch)
    .fetch_one(&mut *transaction)
    .await?;
    let max_sessions = i64::try_from(store.policy.max_concurrent_sessions).unwrap_or(i64::MAX);
    let revoke_count = active_count
        .saturating_sub(max_sessions.saturating_sub(1))
        .max(0);
    let active_sessions: Vec<(i64, Vec<u8>)> = if revoke_count == 0 {
        Vec::new()
    } else {
        crate::sqlx::query_as(
            "SELECT id, token_hash
             FROM user_sessions
             WHERE user_id = $1
               AND revoked_at IS NULL
               AND expires_at > NOW()
               AND last_seen_at > NOW() - $2
               AND session_epoch >= $3
             ORDER BY created_at ASC, id ASC
             LIMIT $4
             FOR UPDATE",
        )
        .bind(user_id)
        .bind(store.idle_timeout_interval())
        .bind(session_epoch)
        .bind(revoke_count)
        .fetch_all(&mut *transaction)
        .await?
    };
    for (session_id, old_token_hash) in active_sessions {
        crate::sqlx::query(
            "UPDATE user_sessions
             SET revoked_at = COALESCE(revoked_at, NOW())
             WHERE id = $1",
        )
        .bind(session_id)
        .execute(&mut *transaction)
        .await?;
        crate::sqlx::query(
            "INSERT INTO session_outbox
                 (operation, session_id, user_id, token_hash, generation)
             VALUES ('revoke_session', $1, $2, $3, $4)",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(old_token_hash)
        .bind(session_epoch)
        .execute(&mut *transaction)
        .await?;
    }
    let id: i64 = crate::sqlx::query_scalar(
        "INSERT INTO user_sessions
             (token_hash, user_id, created_at, expires_at, last_seen_at,
              session_payload, session_epoch)
         VALUES ($1, $2, $3, $4, $5, NULL, $6)
         RETURNING id",
    )
    .bind(&token_hash)
    .bind(user_id)
    .bind(session.created_at)
    .bind(session.expires_at)
    .bind(session.last_seen_at)
    .bind(session_epoch)
    .fetch_one(&mut *transaction)
    .await?;
    session.id = id;
    // 载荷不含明文令牌：token_hash 列已足够定位记录，find() 也用请求令牌覆盖该字段。
    let stored_payload = SessionPayload::from(&*session);
    let encrypted_payload = store.encrypt_payload(&serde_json::to_vec(&stored_payload)?)?;
    crate::sqlx::query("UPDATE user_sessions SET session_payload = $1 WHERE id = $2")
        .bind(encrypted_payload)
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    crate::sqlx::query(
        "INSERT INTO session_outbox
             (operation, session_id, user_id, token_hash, generation)
         VALUES ('sync_session', $1, $2, $3, $4)",
    )
    .bind(id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(session_epoch)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
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
    crate::sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
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
