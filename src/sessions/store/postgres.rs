//! Postgres 权威记录路径（生产部署配置）。
//!
//! 会话元数据写进 `user_sessions` 表，载荷优先从库里取，库里找不到时回退到 Redis。
//! 撤销通过更新 `revoked_at` 列表达，并将撤销通知写进 `session_outbox`，由
//! outbox 处理器异步同步到 Redis。

use std::time::Duration;

use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::{SessionStore, SessionStoreError, SessionSummary};
use crate::{
    sessions::domain::{Session, SessionPayload},
    sqlx::{Postgres, Transaction},
    users::domain::UserId,
};

type SessionMetadataRow = (i64, UserId, OffsetDateTime, OffsetDateTime, Option<Vec<u8>>);

pub(super) async fn save_with_metadata(
    store: &SessionStore,
    session: &mut Session,
    _ttl: Duration,
) -> Result<(), SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let user_id = session
        .user_id
        .parse::<UserId>()
        .map_err(|_| SessionStoreError::InvalidUserId)?;
    let token_hash = Sha256::digest(session.token.as_bytes()).to_vec();
    let mut transaction = pool.begin().await?;
    lock_user_session_scope(&mut transaction, user_id).await?;
    let user_state: Option<(i64, String)> = crate::sqlx::query_as(
        "SELECT session_epoch, status FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((session_epoch, status)) = user_state else {
        return Err(SessionStoreError::UserNotFound);
    };
    if status != "active" {
        return Err(SessionStoreError::UserDisabled);
    }
    let id: i64 = crate::sqlx::query_scalar(
        "INSERT INTO user_sessions
             (token_hash, user_id, created_at, expires_at, session_payload, session_epoch)
         VALUES ($1, $2, $3, $4, NULL, $5)
         RETURNING id",
    )
    .bind(&token_hash)
    .bind(user_id)
    .bind(session.created_at)
    .bind(session.expires_at)
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

pub(super) async fn find_with_metadata(
    store: &SessionStore,
    token: &str,
) -> Result<Option<Session>, SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let token_hash = Sha256::digest(token.as_bytes()).to_vec();
    let metadata: Option<SessionMetadataRow> = crate::sqlx::query_as(
        "SELECT sessions.id, sessions.user_id, sessions.created_at,
                sessions.expires_at, sessions.session_payload
         FROM user_sessions AS sessions
         JOIN users ON users.id = sessions.user_id
         WHERE sessions.token_hash = $1
           AND sessions.revoked_at IS NULL
           AND sessions.expires_at > NOW()
           AND sessions.session_epoch >= users.session_epoch
           AND users.status = 'active'",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;
    let Some((id, user_id, created_at, expires_at, payload)) = metadata else {
        return Ok(None);
    };
    let decoded_payload = if let Some(payload) = payload {
        store.decode_payload(&payload)?
    } else {
        // 库里载荷为 NULL：回退到 Redis 取载荷。
        // 这条路径在 outbox 同步延迟或载荷迁移升级时会走到。
        let mut connection = store.client.get_multiplexed_async_connection().await?;
        let Some(payload): Option<Vec<u8>> = connection.get(store.key(token)).await? else {
            return Ok(None);
        };
        store.decode_payload(&payload)?
    };
    let Some(stored_payload) = decoded_payload else {
        return Ok(None);
    };
    // 令牌只来自请求，不来自存储。
    let mut session = stored_payload.into_session(token.to_owned());
    session.id = id;
    session.user_id = user_id.to_string();
    session.created_at = created_at;
    session.expires_at = expires_at;
    session.revoked_at = None;
    Ok(Some(session))
}

/// 按令牌哈希撤销单条会话。
///
/// 撤销用 `COALESCE(revoked_at, NOW())` 而不是无条件覆盖：重复撤销不应该把
/// 首次撤销时刻往后推，审计需要的是第一次生效的时间。
/// 同时写入 outbox，由处理器把删除动作同步到 Redis 投影。
pub(super) async fn revoke_by_token_hash(
    store: &SessionStore,
    hash: &[u8],
) -> Result<(), SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let mut transaction = pool.begin().await?;
    crate::sqlx::query(
        "UPDATE user_sessions
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE token_hash = $1",
    )
    .bind(hash)
    .execute(&mut *transaction)
    .await?;
    crate::sqlx::query(
        "INSERT INTO session_outbox (operation, token_hash)
         VALUES ('revoke_session', $1)",
    )
    .bind(hash)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub(super) async fn list_for_user(
    store: &SessionStore,
    user_id: UserId,
) -> Result<Vec<SessionSummary>, SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let rows = crate::sqlx::query_as::<_, (i64, OffsetDateTime, OffsetDateTime)>(
        "SELECT sessions.id, sessions.created_at, sessions.expires_at
         FROM user_sessions AS sessions
         JOIN users ON users.id = sessions.user_id
         WHERE sessions.user_id = $1
           AND sessions.revoked_at IS NULL
           AND sessions.expires_at > NOW()
           AND sessions.session_epoch >= users.session_epoch
           AND users.status = 'active'
         ORDER BY sessions.created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, created_at, expires_at)| SessionSummary {
            id,
            created_at,
            expires_at,
        })
        .collect())
}

pub(super) async fn revoke_for_user(
    store: &SessionStore,
    user_id: UserId,
    session_id: i64,
) -> Result<bool, SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let mut transaction = pool.begin().await?;
    lock_user_session_scope(&mut transaction, user_id).await?;
    let found: Option<(Vec<u8>,)> = crate::sqlx::query_as(
        "SELECT token_hash
         FROM user_sessions
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > NOW()
         FOR UPDATE",
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((hash,)) = found else {
        transaction.rollback().await?;
        return Ok(false);
    };
    crate::sqlx::query("UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1")
        .bind(session_id)
        .execute(&mut *transaction)
        .await?;
    crate::sqlx::query(
        "INSERT INTO session_outbox
             (operation, session_id, user_id, token_hash, generation)
         VALUES ('revoke_session', $1, $2, $3, 0)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(&hash)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(true)
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
