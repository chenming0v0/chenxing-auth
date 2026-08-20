//! Session list and per-user revoke under Postgres authority.

use time::OffsetDateTime;

use crate::users::domain::UserId;

use super::super::{SessionStore, SessionStoreError, SessionSummary};

pub(in crate::sessions::store) async fn list_for_user(
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
            AND sessions.last_seen_at > NOW() - MAKE_INTERVAL(secs => sessions.idle_timeout_seconds)
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

pub(in crate::sessions::store) async fn revoke_for_user(
    store: &SessionStore,
    user_id: UserId,
    session_id: i64,
) -> Result<bool, SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let mut transaction = pool.begin().await?;
    super::lock_user_session_scope(&mut transaction, user_id).await?;
    // `session_epoch` 与 token_hash 同行走读，写入 outbox 的 generation：
    // 与其他撤销路径（revoke_by_token_hash、revoke_all_for_user_in_transaction）
    // 一致，让 dead-letter 审计行能按真实 epoch 定位到会话。投递逻辑对
    // revoke_session 只用 token_hash，该字段不改变行为。
    let found: Option<(Vec<u8>, i64)> = crate::sqlx::query_as(
        "SELECT token_hash, session_epoch
          FROM user_sessions
          WHERE id = $1
            AND user_id = $2
            AND revoked_at IS NULL
            AND expires_at > NOW()
            AND last_seen_at > NOW() - MAKE_INTERVAL(secs => idle_timeout_seconds)
          FOR UPDATE",
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((hash, session_epoch)) = found else {
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
         VALUES ('revoke_session', $1, $2, $3, $4)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(&hash)
    .bind(session_epoch)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(true)
}
