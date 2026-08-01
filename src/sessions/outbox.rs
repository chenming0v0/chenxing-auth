use std::time::Duration;

use redis::AsyncCommands;
use time::OffsetDateTime;

use super::store::{SessionStore, SessionStoreError};
use crate::users::domain::UserId;

const OUTBOX_LEASE: time::Duration = time::Duration::minutes(5);

type ClaimedOutboxRow = (
    i64,
    String,
    Option<i64>,
    Option<UserId>,
    Option<Vec<u8>>,
    OffsetDateTime,
    i32,
);

#[derive(Debug)]
struct OutboxEntry {
    id: i64,
    operation: String,
    session_id: Option<i64>,
    user_id: Option<UserId>,
    token_hash: Option<Vec<u8>>,
    created_at: OffsetDateTime,
    attempts: i32,
}

impl SessionStore {
    pub async fn process_pending_outbox(&self) -> Result<usize, SessionStoreError> {
        let Some(pool) = &self.metadata else {
            return Ok(0);
        };
        let ready_before = OffsetDateTime::now_utc();
        let mut processed = 0;
        while let Some(entry) = self.claim_outbox(pool, ready_before).await? {
            match self.apply_outbox(pool, &entry).await {
                Ok(()) => {
                    crate::sqlx::query(
                        "UPDATE session_outbox
                         SET processed_at = NOW(), last_error = NULL
                         WHERE id = $1",
                    )
                    .bind(entry.id)
                    .execute(pool)
                    .await?;
                    processed += 1;
                }
                Err(error_value) => {
                    let delay_seconds = 2_i64
                        .saturating_pow(entry.attempts.saturating_sub(1) as u32)
                        .min(300);
                    let available_at =
                        OffsetDateTime::now_utc() + time::Duration::seconds(delay_seconds);
                    crate::sqlx::query(
                        "UPDATE session_outbox
                         SET available_at = $2, last_error = $3
                         WHERE id = $1",
                    )
                    .bind(entry.id)
                    .bind(available_at)
                    .bind(error_value.to_string())
                    .execute(pool)
                    .await?;
                    tracing::error!(
                        outbox_id = entry.id,
                        operation = %entry.operation,
                        attempts = entry.attempts,
                        error = %error_value,
                        "session Redis projection failed; retry scheduled"
                    );
                }
            }
        }
        Ok(processed)
    }

    pub async fn run_outbox_worker(self) {
        loop {
            if let Err(error_value) = self.process_pending_outbox().await {
                tracing::error!(error = %error_value, "session outbox worker failed");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn claim_outbox(
        &self,
        pool: &crate::sqlx::PgPool,
        ready_before: OffsetDateTime,
    ) -> Result<Option<OutboxEntry>, SessionStoreError> {
        let mut transaction = pool.begin().await?;
        let row: Option<ClaimedOutboxRow> = crate::sqlx::query_as(
            "WITH next AS (
                 SELECT id
                 FROM session_outbox
                 WHERE processed_at IS NULL AND available_at <= $1
                 ORDER BY id
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             UPDATE session_outbox AS outbox
             SET attempts = outbox.attempts + 1,
                 available_at = NOW() + $2
             FROM next
             WHERE outbox.id = next.id
             RETURNING outbox.id, outbox.operation, outbox.session_id, outbox.user_id,
                       outbox.token_hash, outbox.created_at, outbox.attempts",
        )
        .bind(ready_before)
        .bind(OUTBOX_LEASE)
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(row.map(
            |(id, operation, session_id, user_id, token_hash, created_at, attempts)| OutboxEntry {
                id,
                operation,
                session_id,
                user_id,
                token_hash,
                created_at,
                attempts,
            },
        ))
    }

    async fn apply_outbox(
        &self,
        pool: &crate::sqlx::PgPool,
        entry: &OutboxEntry,
    ) -> Result<(), SessionStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        match entry.operation.as_str() {
            "sync_session" => {
                let Some(token_hash) = &entry.token_hash else {
                    return Err(SessionStoreError::InvalidOutbox);
                };
                let Some(session_id) = entry.session_id else {
                    let _: usize = connection.del(self.key_hash(token_hash)).await?;
                    return Ok(());
                };
                // Serialize a projection with revoke/update commits so an old sync cannot win after a revoke.
                let mut transaction = pool.begin().await?;
                let row: Option<(Option<Vec<u8>>, bool, OffsetDateTime)> = crate::sqlx::query_as(
                    "SELECT session_payload, revoked_at IS NULL AND expires_at > NOW(), expires_at
                     FROM user_sessions WHERE id = $1 FOR UPDATE",
                )
                .bind(session_id)
                .fetch_optional(&mut *transaction)
                .await?;
                let Some((payload, active, expires_at)) = row else {
                    let _: usize = connection.del(self.key_hash(token_hash)).await?;
                    transaction.commit().await?;
                    return Ok(());
                };
                if !active {
                    let _: usize = connection.del(self.key_hash(token_hash)).await?;
                    transaction.commit().await?;
                    return Ok(());
                }
                let Some(payload) = payload else {
                    let _: usize = connection.del(self.key_hash(token_hash)).await?;
                    transaction.commit().await?;
                    return Ok(());
                };
                let payload = String::from_utf8(self.decrypt_payload(&payload)?)
                    .map_err(|_| SessionStoreError::PayloadEncoding)?;
                let ttl = (expires_at - OffsetDateTime::now_utc())
                    .whole_seconds()
                    .max(1) as u64;
                connection
                    .set_ex::<_, _, ()>(self.key_hash(token_hash), payload, ttl)
                    .await?;
                transaction.commit().await?;
            }
            "revoke_session" => {
                let Some(token_hash) = &entry.token_hash else {
                    return Err(SessionStoreError::InvalidOutbox);
                };
                let _: usize = connection.del(self.key_hash(token_hash)).await?;
            }
            "revoke_user" => {
                let Some(user_id) = entry.user_id else {
                    return Ok(());
                };
                let hashes: Vec<(Vec<u8>,)> = crate::sqlx::query_as(
                    "SELECT token_hash FROM user_sessions
                     WHERE user_id = $1 AND created_at <= $2",
                )
                .bind(user_id)
                .bind(entry.created_at)
                .fetch_all(pool)
                .await?;
                let keys = hashes
                    .iter()
                    .map(|(hash,)| self.key_hash(hash))
                    .collect::<Vec<_>>();
                if !keys.is_empty() {
                    let _: usize = connection.del(keys).await?;
                }
                let _: () = connection
                    .set(
                        self.revocation_key(&user_id.to_string()),
                        entry.created_at.unix_timestamp_nanos().to_string(),
                    )
                    .await?;
            }
            _ => return Err(SessionStoreError::InvalidOutbox),
        }
        Ok(())
    }
}
