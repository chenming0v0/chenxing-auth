use redis::AsyncCommands;
use time::OffsetDateTime;

use crate::{
    sessions::domain::{Session, SessionLookup, SessionPayload, session_token_hash_bytes},
    users::domain::UserId,
};

use super::super::{SessionStore, SessionStoreError, SessionSummary};

type SessionMetadataRow = (
    i64,
    UserId,
    OffsetDateTime,
    OffsetDateTime,
    OffsetDateTime,
    i64,
    bool,
    Option<Vec<u8>>,
);

pub(super) async fn find_with_metadata(
    store: &SessionStore,
    token: &str,
) -> Result<Option<Session>, SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let token_hash = session_token_hash_bytes(token).to_vec();
    let mut transaction = pool.begin().await?;
    let metadata: Option<SessionMetadataRow> = crate::sqlx::query_as(
        "SELECT sessions.id, sessions.user_id, sessions.created_at,
                 sessions.expires_at, sessions.last_seen_at, sessions.session_epoch,
                 sessions.last_seen_at <= NOW() - $3 AS needs_renewal,
                 sessions.session_payload
          FROM user_sessions AS sessions
          JOIN users ON users.id = sessions.user_id
          WHERE sessions.token_hash = $1
            AND sessions.revoked_at IS NULL
            AND sessions.expires_at > NOW()
            AND sessions.last_seen_at > NOW() - $2
            AND sessions.session_epoch >= users.session_epoch
            AND users.status = 'active'
          FOR UPDATE OF sessions",
    )
    .bind(&token_hash)
    .bind(store.idle_timeout_interval())
    .bind(store.renewal_interval())
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((
        id,
        user_id,
        created_at,
        expires_at,
        last_seen_at,
        session_epoch,
        needs_renewal,
        payload,
    )) = metadata
    else {
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
    session.last_seen_at = last_seen_at;
    session.revoked_at = None;
    session.set_idle_timeout(store.policy.idle_timeout);
    if needs_renewal {
        let renewed_at: OffsetDateTime = crate::sqlx::query_scalar(
            "UPDATE user_sessions
             SET last_seen_at = NOW()
             WHERE id = $1
             RETURNING last_seen_at",
        )
        .bind(id)
        .fetch_one(&mut *transaction)
        .await?;
        session.last_seen_at = renewed_at;
        let stored_payload = SessionPayload::from(&session);
        let encrypted_payload = store.encrypt_payload(&serde_json::to_vec(&stored_payload)?)?;
        crate::sqlx::query("UPDATE user_sessions SET session_payload = $1 WHERE id = $2")
            .bind(encrypted_payload)
            .bind(id)
            .execute(&mut *transaction)
            .await?;
        enqueue_sync_event(&mut transaction, id, user_id, &token_hash, session_epoch).await?;
    }
    transaction.commit().await?;
    Ok(Some(session))
}

async fn enqueue_sync_event(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    session_id: i64,
    user_id: UserId,
    token_hash: &[u8],
    generation: i64,
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query(
        "INSERT INTO session_outbox
             (operation, session_id, user_id, token_hash, generation)
         VALUES ('sync_session', $1, $2, $3, $4)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(token_hash)
    .bind(generation)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn find_with_metadata_by_token_hash(
    store: &SessionStore,
    token_hash: &[u8],
) -> Result<Option<SessionLookup>, SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let mut transaction = pool.begin().await?;
    let metadata: Option<(
        i64,
        UserId,
        OffsetDateTime,
        OffsetDateTime,
        OffsetDateTime,
        i64,
        bool,
    )> = crate::sqlx::query_as(
        "SELECT sessions.id, sessions.user_id, sessions.created_at,
                    sessions.expires_at, sessions.last_seen_at, sessions.session_epoch,
                    sessions.last_seen_at <= NOW() - $3 AS needs_renewal
             FROM user_sessions AS sessions
             JOIN users ON users.id = sessions.user_id
             WHERE sessions.token_hash = $1
               AND sessions.revoked_at IS NULL
               AND sessions.expires_at > NOW()
               AND sessions.last_seen_at > NOW() - $2
               AND sessions.session_epoch >= users.session_epoch
               AND users.status = 'active'
             FOR UPDATE OF sessions",
    )
    .bind(token_hash.to_vec())
    .bind(store.idle_timeout_interval())
    .bind(store.renewal_interval())
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((id, user_id, created_at, expires_at, last_seen_at, generation, needs_renewal)) =
        metadata
    else {
        return Ok(None);
    };
    let last_seen_at = if needs_renewal {
        let renewed_at: OffsetDateTime = crate::sqlx::query_scalar(
            "UPDATE user_sessions
             SET last_seen_at = NOW()
             WHERE id = $1
             RETURNING last_seen_at",
        )
        .bind(id)
        .fetch_one(&mut *transaction)
        .await?;
        enqueue_sync_event(&mut transaction, id, user_id, token_hash, generation).await?;
        renewed_at
    } else {
        last_seen_at
    };
    transaction.commit().await?;
    Ok(Some(
        SessionLookup {
            id,
            user_id: user_id.to_string(),
            created_at,
            expires_at,
            last_seen_at,
            revoked_at: None,
            idle_timeout: None,
        }
        .with_idle_timeout(store.policy.idle_timeout),
    ))
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
            AND sessions.last_seen_at > NOW() - $2
            AND sessions.session_epoch >= users.session_epoch
            AND users.status = 'active'
          ORDER BY sessions.created_at DESC",
    )
    .bind(user_id)
    .bind(store.idle_timeout_interval())
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
    super::lock_user_session_scope(&mut transaction, user_id).await?;
    let found: Option<(Vec<u8>,)> = crate::sqlx::query_as(
        "SELECT token_hash
          FROM user_sessions
          WHERE id = $1
            AND user_id = $2
            AND revoked_at IS NULL
            AND expires_at > NOW()
            AND last_seen_at > NOW() - $3
          FOR UPDATE",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(store.idle_timeout_interval())
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
