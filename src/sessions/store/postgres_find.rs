//! Metadata-enabled session lookup (Issue #432).
//!
//! Hot path is an unlocked PostgreSQL read. Redis is only a legacy payload
//! fallback and must never run under a session row lock. `FOR UPDATE` is taken
//! only for the short renewal write that bumps `last_seen_at` and backfills the
//! encrypted payload.

use redis::AsyncCommands;
use time::OffsetDateTime;

use crate::{
    sessions::domain::{Session, SessionLookup, SessionPayload, session_token_hash_bytes},
    users::domain::UserId,
};

use super::super::{SessionStore, SessionStoreError};

/// Columns returned by the unlocked active-session lookup.
type ActiveSessionSqlRow = (
    i64,
    UserId,
    OffsetDateTime,
    OffsetDateTime,
    OffsetDateTime,
    i64,
    bool,
    Option<Vec<u8>>,
);

impl From<ActiveSessionSqlRow> for ActiveSessionRow {
    fn from(
        (
            id,
            user_id,
            created_at,
            expires_at,
            last_seen_at,
            session_epoch,
            needs_renewal,
            payload,
        ): ActiveSessionSqlRow,
    ) -> Self {
        Self {
            id,
            user_id,
            created_at,
            expires_at,
            last_seen_at,
            session_epoch,
            needs_renewal,
            payload,
        }
    }
}

struct ActiveSessionRow {
    id: i64,
    user_id: UserId,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    session_epoch: i64,
    needs_renewal: bool,
    payload: Option<Vec<u8>>,
}

pub(in crate::sessions::store) async fn find_with_metadata(
    store: &SessionStore,
    token: &str,
) -> Result<Option<Session>, SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;
    let token_hash = session_token_hash_bytes(token).to_vec();

    // Unlocked authority check. Holding FOR UPDATE here would pin the row for
    // the entire find — including Redis fallback I/O on migration rows.
    let Some(row) = load_active_by_token_hash(pool, store, &token_hash).await? else {
        return Ok(None);
    };

    // Payload resolution is lock-free: PG ciphertext first, Redis only when the
    // durable column is still NULL (pre-backfill / delayed outbox).
    let used_redis_fallback = row.payload.is_none();
    let Some(stored_payload) =
        resolve_session_payload(store, token, row.id, row.payload.as_deref()).await?
    else {
        return Ok(None);
    };

    // After external I/O, re-check authority without taking a lock. Shrinks the
    // window where a revoke that committed during Redis fallback would otherwise
    // still authenticate. Renewal path re-validates again under FOR UPDATE.
    if used_redis_fallback && !session_still_active(pool, store, row.id).await? {
        return Ok(None);
    }

    // Token only comes from the request, never from storage.
    let mut session = stored_payload.into_session(token.to_owned());
    session.id = row.id;
    session.user_id = row.user_id.to_string();
    session.created_at = row.created_at;
    session.expires_at = row.expires_at;
    session.last_seen_at = row.last_seen_at;
    session.revoked_at = None;
    session.set_credential_generation(row.session_epoch);
    session.set_idle_timeout(store.policy.idle_timeout);

    if row.needs_renewal {
        let Some(renewed_at) = renew_session_activity(
            store,
            pool,
            row.id,
            row.user_id,
            &token_hash,
            row.session_epoch,
            Some(&session),
        )
        .await?
        else {
            // Revoked, expired, or otherwise terminal between the unlocked read
            // and the renewal lock — fail closed.
            return Ok(None);
        };
        session.last_seen_at = renewed_at;
    }

    Ok(Some(session))
}

pub(in crate::sessions::store) async fn find_with_metadata_by_token_hash(
    store: &SessionStore,
    token_hash: &[u8],
) -> Result<Option<SessionLookup>, SessionStoreError> {
    let pool = store
        .metadata
        .as_ref()
        .ok_or(SessionStoreError::MetadataUnavailable)?;

    let Some(row) = load_active_by_token_hash(pool, store, token_hash).await? else {
        return Ok(None);
    };

    let last_seen_at = if row.needs_renewal {
        // Hash-only callers never reconstruct CSRF material, so renewal only
        // bumps activity + outbox — same as the pre-#432 path.
        let Some(renewed_at) = renew_session_activity(
            store,
            pool,
            row.id,
            row.user_id,
            token_hash,
            row.session_epoch,
            None,
        )
        .await?
        else {
            return Ok(None);
        };
        renewed_at
    } else {
        row.last_seen_at
    };

    Ok(Some(
        SessionLookup {
            id: row.id,
            user_id: row.user_id.to_string(),
            created_at: row.created_at,
            expires_at: row.expires_at,
            last_seen_at,
            revoked_at: None,
            idle_timeout: None,
        }
        .with_idle_timeout(store.policy.idle_timeout),
    ))
}

async fn load_active_by_token_hash(
    pool: &crate::sqlx::PgPool,
    store: &SessionStore,
    token_hash: &[u8],
) -> Result<Option<ActiveSessionRow>, SessionStoreError> {
    let row = crate::sqlx::query_as::<_, ActiveSessionSqlRow>(
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
           AND users.status = 'active'",
    )
    .bind(token_hash)
    .bind(store.idle_timeout_interval())
    .bind(store.renewal_interval())
    .fetch_optional(pool)
    .await?;

    Ok(row.map(ActiveSessionRow::from))
}

/// Cheap unlocked liveness probe used after Redis fallback.
async fn session_still_active(
    pool: &crate::sqlx::PgPool,
    store: &SessionStore,
    session_id: i64,
) -> Result<bool, SessionStoreError> {
    let active: Option<bool> = crate::sqlx::query_scalar(
        "SELECT TRUE
         FROM user_sessions AS sessions
         JOIN users ON users.id = sessions.user_id
         WHERE sessions.id = $1
           AND sessions.revoked_at IS NULL
           AND sessions.expires_at > NOW()
           AND sessions.last_seen_at > NOW() - $2
           AND sessions.session_epoch >= users.session_epoch
           AND users.status = 'active'",
    )
    .bind(session_id)
    .bind(store.idle_timeout_interval())
    .fetch_optional(pool)
    .await?;
    Ok(active.unwrap_or(false))
}

/// Resolve the CSRF-bearing payload without any open Postgres transaction.
async fn resolve_session_payload(
    store: &SessionStore,
    token: &str,
    session_id: i64,
    pg_payload: Option<&[u8]>,
) -> Result<Option<SessionPayload>, SessionStoreError> {
    if let Some(payload) = pg_payload {
        return store.decode_payload(payload);
    }

    // Redis is a projection. Connection/read failures are treated as "session
    // absent" — same fail-closed posture as decrypt failure — so a flaky Redis
    // cannot 500 every pre-backfill session. Warn for operators.
    let mut connection = match store.client.get_multiplexed_async_connection().await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::warn!(
                error = %error,
                session_id,
                stage = "connect",
                "redis session payload fallback failed; treating session as absent"
            );
            return Ok(None);
        }
    };
    let payload: Option<Vec<u8>> = match connection.get(store.key(token)).await {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(
                error = %error,
                session_id,
                stage = "read",
                "redis session payload fallback failed; treating session as absent"
            );
            return Ok(None);
        }
    };
    let Some(payload) = payload else {
        return Ok(None);
    };
    store.decode_payload(&payload)
}

/// Short locked write for idle renewal only.
///
/// Returns `Ok(None)` when the row is no longer active under the lock (revoke /
/// expiry / epoch race). Returns the authoritative `last_seen_at` otherwise —
/// either freshly bumped or left alone if a concurrent finder already renewed.
///
/// When `payload_source` is `Some`, the renewal also backfills `session_payload`
/// (token find). Hash-only find passes `None` and only touches activity + outbox.
async fn renew_session_activity(
    store: &SessionStore,
    pool: &crate::sqlx::PgPool,
    session_id: i64,
    user_id: UserId,
    token_hash: &[u8],
    session_epoch: i64,
    payload_source: Option<&Session>,
) -> Result<Option<OffsetDateTime>, SessionStoreError> {
    let mut transaction = pool.begin().await?;
    let locked: Option<(OffsetDateTime, bool)> = crate::sqlx::query_as(
        "SELECT sessions.last_seen_at,
                sessions.last_seen_at <= NOW() - $3 AS needs_renewal
         FROM user_sessions AS sessions
         JOIN users ON users.id = sessions.user_id
         WHERE sessions.id = $1
           AND sessions.revoked_at IS NULL
           AND sessions.expires_at > NOW()
           AND sessions.last_seen_at > NOW() - $2
           AND sessions.session_epoch >= users.session_epoch
           AND users.status = 'active'
         FOR UPDATE OF sessions",
    )
    .bind(session_id)
    .bind(store.idle_timeout_interval())
    .bind(store.renewal_interval())
    .fetch_optional(&mut *transaction)
    .await?;

    let Some((current_last_seen, still_needs_renewal)) = locked else {
        return Ok(None);
    };

    let last_seen_at = if still_needs_renewal {
        let renewed_at: OffsetDateTime = crate::sqlx::query_scalar(
            "UPDATE user_sessions
             SET last_seen_at = NOW()
             WHERE id = $1
             RETURNING last_seen_at",
        )
        .bind(session_id)
        .fetch_one(&mut *transaction)
        .await?;

        if let Some(session) = payload_source {
            let mut renewed = session.clone();
            renewed.last_seen_at = renewed_at;
            let stored_payload = SessionPayload::from(&renewed);
            let encrypted_payload = store.encrypt_payload(&serde_json::to_vec(&stored_payload)?)?;
            crate::sqlx::query("UPDATE user_sessions SET session_payload = $1 WHERE id = $2")
                .bind(encrypted_payload)
                .bind(session_id)
                .execute(&mut *transaction)
                .await?;
        }

        enqueue_sync_event(
            &mut transaction,
            session_id,
            user_id,
            token_hash,
            session_epoch,
        )
        .await?;
        renewed_at
    } else {
        current_last_seen
    };

    transaction.commit().await?;
    Ok(Some(last_seen_at))
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
