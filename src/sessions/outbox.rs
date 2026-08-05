use std::time::Duration;

use redis::{AsyncCommands, Script};
use time::OffsetDateTime;

use super::store::{SessionStore, SessionStoreError};
use crate::users::domain::UserId;

const OUTBOX_LEASE: time::Duration = time::Duration::minutes(5);
const CONDITIONAL_SESSION_SET: &str = "local marker = redis.call('GET', KEYS[1])\nif marker and tonumber(marker) > tonumber(ARGV[1]) then return 0 end\nredis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])\nreturn 1";
const ADVANCE_REVOCATION_EPOCH: &str = "local current = redis.call('GET', KEYS[1])\nif not current or tonumber(current) < tonumber(ARGV[1]) then redis.call('SET', KEYS[1], ARGV[1]) end\nreturn 1";

type ClaimedOutboxRow = (
    i64,
    String,
    Option<i64>,
    Option<UserId>,
    Option<Vec<u8>>,
    i32,
    i64,
);
type SessionProjectionRow = (Option<Vec<u8>>, bool, OffsetDateTime, i64, UserId);

#[derive(Debug)]
struct OutboxEntry {
    id: i64,
    operation: String,
    session_id: Option<i64>,
    user_id: Option<UserId>,
    token_hash: Option<Vec<u8>>,
    attempts: i32,
    generation: i64,
}

impl SessionStore {
    pub async fn process_pending_outbox(&self) -> Result<usize, SessionStoreError> {
        let Some(pool) = &self.metadata else {
            return Ok(0);
        };
        let mut processed = 0;
        while let Some(entry) = self.claim_outbox(pool).await? {
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
                    crate::sqlx::query(
                        "UPDATE session_outbox
                         SET available_at = NOW() + $2, last_error = $3
                         WHERE id = $1",
                    )
                    .bind(entry.id)
                    .bind(time::Duration::seconds(delay_seconds))
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
    ) -> Result<Option<OutboxEntry>, SessionStoreError> {
        let mut transaction = pool.begin().await?;
        let row: Option<ClaimedOutboxRow> = crate::sqlx::query_as(
            "WITH next AS (
                 SELECT id
                 FROM session_outbox
                 WHERE processed_at IS NULL AND available_at <= NOW()
                 ORDER BY id
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             UPDATE session_outbox AS outbox
             SET attempts = outbox.attempts + 1,
                 available_at = NOW() + $1
             FROM next
             WHERE outbox.id = next.id
             RETURNING outbox.id, outbox.operation, outbox.session_id, outbox.user_id,
                       outbox.token_hash, outbox.attempts, outbox.generation",
        )
        .bind(OUTBOX_LEASE)
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(row.map(
            |(id, operation, session_id, user_id, token_hash, attempts, generation)| OutboxEntry {
                id,
                operation,
                session_id,
                user_id,
                token_hash,
                attempts,
                generation,
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
                let mut transaction = pool.begin().await?;
                let row: Option<SessionProjectionRow> = crate::sqlx::query_as(
                    "SELECT sessions.session_payload,
                                sessions.revoked_at IS NULL
                                    AND sessions.expires_at > NOW()
                                    AND sessions.session_epoch >= users.session_epoch
                                    AND users.status = 'active',
                                sessions.expires_at, sessions.session_epoch, sessions.user_id
                         FROM user_sessions AS sessions
                         JOIN users ON users.id = sessions.user_id
                         WHERE sessions.id = $1
                         FOR UPDATE OF sessions",
                )
                .bind(session_id)
                .fetch_optional(&mut *transaction)
                .await?;
                let Some((payload, active, expires_at, generation, user_id)) = row else {
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
                // 始终重新加密投影：旧密钥写入的载荷在迁移期仍可读，且明文不落入 Redis。
                // 这里额外经过 SessionPayload 归一化——升级前写入的载荷含明文 token 字段，
                // 解析后重新序列化会把它剥离，否则历史会话会继续在 Redis 留下可用令牌。
                let Some(payload) = self
                    .decode_payload(&payload)?
                    .and_then(|stored| serde_json::to_vec(&stored).ok())
                    .and_then(|payload| self.encrypt_payload(&payload).ok())
                else {
                    let _: usize = connection.del(self.key_hash(token_hash)).await?;
                    transaction.commit().await?;
                    return Ok(());
                };
                let ttl = (expires_at - OffsetDateTime::now_utc())
                    .whole_seconds()
                    .max(1) as u64;
                let _: i64 = Script::new(CONDITIONAL_SESSION_SET)
                    .key(self.revocation_key(&user_id.to_string()))
                    .key(self.key_hash(token_hash))
                    .arg(generation)
                    .arg(payload)
                    .arg(ttl)
                    .invoke_async(&mut connection)
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
                     WHERE user_id = $1 AND session_epoch < $2",
                )
                .bind(user_id)
                .bind(entry.generation)
                .fetch_all(pool)
                .await?;
                let keys = hashes
                    .iter()
                    .map(|(hash,)| self.key_hash(hash))
                    .collect::<Vec<_>>();
                if !keys.is_empty() {
                    let _: usize = connection.del(keys).await?;
                }
                let _: i64 = Script::new(ADVANCE_REVOCATION_EPOCH)
                    .key(self.revocation_key(&user_id.to_string()))
                    .arg(entry.generation)
                    .invoke_async(&mut connection)
                    .await?;
            }
            _ => return Err(SessionStoreError::InvalidOutbox),
        }
        Ok(())
    }
}
