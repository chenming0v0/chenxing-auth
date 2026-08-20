use redis::{AsyncCommands, Script};
use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;

use super::store::{SessionStore, SessionStoreError};
use crate::users::domain::UserId;

#[path = "outbox_retention.rs"]
mod retention;

pub use retention::{OutboxCleanup, SessionOutboxPolicy};

const OUTBOX_LEASE: time::Duration = time::Duration::minutes(5);
const CONDITIONAL_SESSION_SET: &str = "local marker = redis.call('GET', KEYS[1])\nif marker and tonumber(marker) > tonumber(ARGV[1]) then return 0 end\nredis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])\nreturn 1";
/// 用户级撤销水位单调前进，并始终带上过期时间。
///
/// `ARGV[2]` 是水位 TTL（秒），取绝对 Session TTL。水位只需覆盖"可能被它拦截的
/// 会话键"的存活窗口：会话键 TTL 同样被绝对 Session TTL 封顶，且写入时刻不晚于
/// 本次水位写入时刻，所以旧会话不可能活到水位过期之后。
///
/// 值不前进时也要刷新 TTL：重复投递、乱序重试和升级前留下的无 TTL 老键都会走到
/// 这条分支，只有在这里补 `EXPIRE` 才能让它们最终被回收。刷新只延长、不缩短，
/// `TTL` 返回的 -1（无过期）天然小于目标值，不需要单独判断。
const ADVANCE_REVOCATION_EPOCH: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or tonumber(current) < tonumber(ARGV[1]) then
    redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
elseif redis.call('TTL', KEYS[1]) < tonumber(ARGV[2]) then
    redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 1
"#;

type ClaimedOutboxRow = (
    i64,
    String,
    Option<i64>,
    Option<UserId>,
    Option<Vec<u8>>,
    i32,
    i64,
    i64,
    String,
);
type SessionProjectionRow = (Option<Vec<u8>>, bool, i64, OffsetDateTime, i64, UserId);

struct OutboxEntry {
    id: i64,
    operation: String,
    session_id: Option<i64>,
    user_id: Option<UserId>,
    token_hash: Option<Vec<u8>>,
    /// 领取时自增后的尝试次数，从 1 开始。dead-letter 判定直接比较这个值。
    attempts: i32,
    generation: i64,
    claim_generation: i64,
    claim_token: String,
}

impl fmt::Debug for OutboxEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboxEntry")
            .field("id", &self.id)
            .field("operation", &self.operation)
            .field("session_id", &self.session_id)
            .field("user_id", &self.user_id)
            .field("token_hash", &"<redacted>")
            .field("attempts", &self.attempts)
            .field("generation", &self.generation)
            .field("claim_generation", &self.claim_generation)
            .finish()
    }
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
                    // `dead_lettered_at = NULL` 处理一种租约边界情况：另一个实例
                    // 的租约到期后本实例重新领取了同一行，而那个实例随后判定它
                    // 用尽预算并写了 dead-letter。投递确实成功了，终态必须收敛到
                    // processed；CHECK 约束也不允许两个终态时间戳同时非空。
                    let outcome = crate::sqlx::query(
                        "UPDATE session_outbox
                         SET processed_at = NOW(), dead_lettered_at = NULL, last_error = NULL
                         WHERE id = $1 AND claim_generation = $2 AND claim_token = $3",
                    )
                    .bind(entry.id)
                    .bind(entry.claim_generation)
                    .bind(&entry.claim_token)
                    .execute(pool)
                    .await?;
                    if outcome.rows_affected() == 1 {
                        processed += 1;
                    } else {
                        tracing::warn!(
                            outbox_id = entry.id,
                            claim_generation = entry.claim_generation,
                            event = "session_outbox.stale_claim",
                            "stale session outbox completion ignored"
                        );
                    }
                }
                Err(error_value) => {
                    self.record_delivery_failure(pool, &entry, &error_value)
                        .await?;
                }
            }
        }
        Ok(processed)
    }

    async fn claim_outbox(
        &self,
        pool: &crate::sqlx::PgPool,
    ) -> Result<Option<OutboxEntry>, SessionStoreError> {
        let mut transaction = pool.begin().await?;
        // dead-letter 行被排除在领取之外，这是"不再无限重试"的实际执行点：
        // `session_outbox_pending_idx` 的部分条件与这里的 WHERE 一致，坏行既不在
        // 索引里，也不会被扫到。
        let claim_token = Uuid::new_v4().simple().to_string();
        let row: Option<ClaimedOutboxRow> = crate::sqlx::query_as(
            "WITH next AS (
                 SELECT id
                 FROM session_outbox
                 WHERE processed_at IS NULL
                   AND dead_lettered_at IS NULL
                   AND available_at <= NOW()
                 ORDER BY id
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             UPDATE session_outbox AS outbox
             SET attempts = outbox.attempts + 1,
                     claim_generation = outbox.claim_generation + 1,
                     claim_token = $2,
                     available_at = NOW() + $1
             FROM next
             WHERE outbox.id = next.id
             RETURNING outbox.id, outbox.operation, outbox.session_id, outbox.user_id,
                       outbox.token_hash, outbox.attempts, outbox.generation,
                       outbox.claim_generation, outbox.claim_token",
        )
        .bind(OUTBOX_LEASE)
        .bind(&claim_token)
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(row.map(
            |(
                id,
                operation,
                session_id,
                user_id,
                token_hash,
                attempts,
                generation,
                claim_generation,
                claim_token,
            )| OutboxEntry {
                id,
                operation,
                session_id,
                user_id,
                token_hash,
                attempts,
                generation,
                claim_generation,
                claim_token,
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
                                    AND sessions.last_seen_at + $2 > NOW()
                                    AND sessions.session_epoch >= users.session_epoch
                                    AND users.status = 'active',
                                EXTRACT(EPOCH FROM LEAST(
                                    sessions.expires_at,
                                    sessions.last_seen_at + $2
                                ) - NOW())::bigint,
                                sessions.last_seen_at,
                                sessions.session_epoch, sessions.user_id
                         FROM user_sessions AS sessions
                         JOIN users ON users.id = sessions.user_id
                         WHERE sessions.id = $1
                         FOR UPDATE OF sessions",
                )
                .bind(session_id)
                .bind(self.idle_timeout_interval())
                .fetch_optional(&mut *transaction)
                .await?;
                let Some((payload, active, remaining_seconds, last_seen_at, generation, user_id)) =
                    row
                else {
                    let _: usize = connection.del(self.key_hash(token_hash)).await?;
                    transaction.commit().await?;
                    return Ok(());
                };
                let payload = match (active, payload) {
                    // PostgreSQL is authoritative for lifecycle state. Never preserve a
                    // fallback payload after revocation, expiry, idle timeout, epoch
                    // revocation, or user disablement.
                    (false, _) => {
                        let _: usize = connection.del(self.key_hash(token_hash)).await?;
                        transaction.commit().await?;
                        return Ok(());
                    }
                    // During payload migration an active row can legitimately have no
                    // PostgreSQL payload. Redis is then the only payload source used by
                    // `find_authenticated_with_metadata`; a sync event must leave that fallback intact.
                    (true, None) => {
                        transaction.commit().await?;
                        return Ok(());
                    }
                    (true, Some(payload)) => payload,
                };
                // 始终重新加密投影：旧密钥写入的载荷在迁移期仍可读，且明文不落入 Redis。
                // 解析后重新序列化会把升级前载荷中的明文 token 剥离，同时把权威
                // last_seen_at 写回投影，避免续期事件留下旧的 idle 时间。
                let Some(mut stored_payload) = self.decode_payload(&payload)? else {
                    let _: usize = connection.del(self.key_hash(token_hash)).await?;
                    transaction.commit().await?;
                    return Ok(());
                };
                stored_payload.last_seen_at = Some(last_seen_at);
                let payload = self.encrypt_payload(&serde_json::to_vec(&stored_payload)?)?;
                // 投影 TTL 同样被撤销水位 TTL 封顶：水位在撤销时刻带 `EX` 写入，
                // 只有会话键活得不比水位久，旧会话才不可能在水位过期后被放行。
                //
                // `remaining_seconds` 由 SQL 用数据库事务时间 `NOW()` 直接算出，
                // 与上面 `active` 判定同源，不再混入进程时钟：进程钟领先会让
                // TTL 被压到 1 秒、投影立即消失，落后则会让投影超期存活。
                let seconds = remaining_seconds.max(1) as u64;
                let ttl = seconds.min(self.revocation_ttl_seconds());
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
                    .arg(self.revocation_ttl_seconds())
                    .invoke_async(&mut connection)
                    .await?;
            }
            _ => return Err(SessionStoreError::InvalidOutbox),
        }
        Ok(())
    }
}
