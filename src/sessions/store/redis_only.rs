//! 纯 Redis 会话路径（未配置 Postgres 元数据时使用）。
//!
//! 这条路径没有权威记录可查，撤销只能靠"撤销水位"表达：把撤销时刻写进
//! `revoked-before:{user_id}`，此后所有 `created_at` 不晚于该时刻的会话一律判为无效。
//! 因此写入和判定都必须与水位比较，且比较要在 Redis 侧原子完成——
//! 先读水位再写会话的两步实现会让并发撤销和登录互相穿越。
//! 单条撤销另外保留一个按令牌哈希索引的短期 tombstone，防止续期请求在
//! `DEL` 之后把同一会话重新写回；tombstone TTL 取绝对 Session TTL。

use std::time::Duration;

use redis::{AsyncCommands, Script};
use time::OffsetDateTime;

use super::{SessionStore, SessionStoreError, timestamp_watermark};
use crate::{
    sessions::domain::{Session, SessionLookup, SessionPayload, session_token_hash_bytes},
    users::domain::UserId,
};

/// 写入会话前先比对撤销水位：水位不早于会话创建时刻则拒绝写入（返回 0）。
/// 判定与写入在同一个 Lua 脚本里完成，保证原子性。
const REDIS_ONLY_SESSION_SET: &str = "local marker = redis.call('GET', KEYS[1])\nif marker and tonumber(marker) >= tonumber(ARGV[1]) then return 0 end\nif redis.call('EXISTS', KEYS[3]) == 1 then return 0 end\nredis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])\nreturn 1";
const REDIS_ONLY_REVOKE_SESSION: &str =
    "redis.call('DEL', KEYS[1])\nredis.call('SET', KEYS[2], '1', 'EX', ARGV[1])\nreturn 1";
/// 水位单调前进：只在新值更大时覆盖，避免乱序请求把水位往回拨。
const REDIS_ONLY_ADVANCE_WATERMARK: &str = "local current = redis.call('GET', KEYS[1])\nif not current or tonumber(current) < tonumber(ARGV[1]) then redis.call('SET', KEYS[1], ARGV[1]) end\nreturn 1";

pub(super) async fn save_redis_only(
    store: &SessionStore,
    session: &Session,
    ttl: Duration,
) -> Result<(), SessionStoreError> {
    // 只序列化 SessionPayload：明文会话令牌不进入持久化载荷，
    // Redis 键本身已经由令牌的 SHA-256 派生，读取时由调用方补回 token。
    let stored_payload = SessionPayload::from(session);
    let payload = store.encrypt_payload(&serde_json::to_vec(&stored_payload)?)?;
    let mut connection = store.client.get_multiplexed_async_connection().await?;
    let created_at = timestamp_watermark(session.created_at);
    let ttl_seconds = store.redis_ttl_seconds(session, ttl, OffsetDateTime::now_utc());
    let stored: i64 = Script::new(REDIS_ONLY_SESSION_SET)
        .key(store.redis_only_revocation_key(&session.user_id))
        .key(store.key(&session.token))
        .key(store.redis_only_token_revocation_key(&session_token_hash_bytes(&session.token)))
        .arg(created_at)
        .arg(payload)
        .arg(ttl_seconds)
        .invoke_async(&mut connection)
        .await?;
    if stored == 0 {
        return Err(SessionStoreError::SessionRevoked);
    }
    Ok(())
}

pub(super) async fn find_redis_only(
    store: &SessionStore,
    token: &str,
) -> Result<Option<Session>, SessionStoreError> {
    let mut connection = store.client.get_multiplexed_async_connection().await?;
    let payload: Option<Vec<u8>> = connection.get(store.key(token)).await?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let Some(stored_payload) = store.decode_payload(&payload)? else {
        return Ok(None);
    };
    // Redis 键由令牌哈希派生，能读到这条记录就说明调用方持有该令牌。
    let mut session = stored_payload.into_session(token.to_owned());
    session.set_idle_timeout(store.policy.idle_timeout);
    let now = OffsetDateTime::now_utc();
    if !session.is_active_at(now) {
        return Ok(None);
    }
    let marker: Option<String> = connection
        .get(store.redis_only_revocation_key(&session.user_id))
        .await?;
    let token_revocation: Option<String> = connection
        .get(store.redis_only_token_revocation_key(&session_token_hash_bytes(token)))
        .await?;
    if token_revocation.is_some() {
        return Ok(None);
    }
    // 水位判定用 `<=`：与撤销时刻同一纳秒创建的会话也必须失效，
    // 否则撤销与登录在同一时刻竞争时会漏放一条会话。
    if marker
        .and_then(|value| value.parse::<i128>().ok())
        .is_some_and(|before| session.created_at.unix_timestamp_nanos() <= before)
    {
        return Ok(None);
    }
    if session.last_seen_at <= now - store.renewal_interval() {
        session.last_seen_at = now;
        let payload =
            store.encrypt_payload(&serde_json::to_vec(&SessionPayload::from(&session))?)?;
        let stored: i64 = Script::new(REDIS_ONLY_SESSION_SET)
            .key(store.redis_only_revocation_key(&session.user_id))
            .key(store.key(&session.token))
            .key(store.redis_only_token_revocation_key(&session_token_hash_bytes(&session.token)))
            .arg(timestamp_watermark(session.created_at))
            .arg(payload)
            .arg(store.redis_ttl_seconds(&session, Duration::from_secs(u64::MAX), now))
            .invoke_async(&mut connection)
            .await?;
        if stored == 0 {
            return Ok(None);
        }
    }
    Ok(Some(session))
}

pub(super) async fn find_redis_only_by_token_hash(
    store: &SessionStore,
    token_hash: &[u8],
) -> Result<Option<SessionLookup>, SessionStoreError> {
    let mut connection = store.client.get_multiplexed_async_connection().await?;
    let payload: Option<Vec<u8>> = connection.get(store.key_hash(token_hash)).await?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let Some(stored_payload) = store.decode_payload(&payload)? else {
        return Ok(None);
    };
    let mut session = stored_payload.into_session(String::new());
    session.set_idle_timeout(store.policy.idle_timeout);
    let now = OffsetDateTime::now_utc();
    if !session.is_active_at(now) {
        return Ok(None);
    }
    let marker: Option<String> = connection
        .get(store.redis_only_revocation_key(&session.user_id))
        .await?;
    let token_revocation: Option<String> = connection
        .get(store.redis_only_token_revocation_key(token_hash))
        .await?;
    if token_revocation.is_some() {
        return Ok(None);
    }
    if marker
        .and_then(|value| value.parse::<i128>().ok())
        .is_some_and(|before| session.created_at.unix_timestamp_nanos() <= before)
    {
        return Ok(None);
    }
    if session.last_seen_at <= now - store.renewal_interval() {
        session.last_seen_at = now;
        let payload =
            store.encrypt_payload(&serde_json::to_vec(&SessionPayload::from(&session))?)?;
        let stored: i64 = Script::new(REDIS_ONLY_SESSION_SET)
            .key(store.redis_only_revocation_key(&session.user_id))
            .key(store.key_hash(token_hash))
            .key(store.redis_only_token_revocation_key(token_hash))
            .arg(timestamp_watermark(session.created_at))
            .arg(payload)
            .arg(store.redis_ttl_seconds(&session, Duration::from_secs(u64::MAX), now))
            .invoke_async(&mut connection)
            .await?;
        if stored == 0 {
            return Ok(None);
        }
    }
    Ok(Some(
        SessionPayload::from(&session)
            .into_lookup()
            .with_idle_timeout(store.policy.idle_timeout),
    ))
}

pub(super) async fn revoke_redis_only(
    store: &SessionStore,
    hash: &[u8],
) -> Result<(), SessionStoreError> {
    let mut connection = store.client.get_multiplexed_async_connection().await?;
    let _: i64 = Script::new(REDIS_ONLY_REVOKE_SESSION)
        .key(store.key_hash(hash))
        .key(store.redis_only_token_revocation_key(hash))
        .arg(store.revocation_ttl_seconds())
        .invoke_async(&mut connection)
        .await?;
    Ok(())
}

pub(super) async fn revoke_all_redis_only(
    store: &SessionStore,
    user_id: UserId,
) -> Result<(), SessionStoreError> {
    let mut connection = store.client.get_multiplexed_async_connection().await?;
    let _: i64 = Script::new(REDIS_ONLY_ADVANCE_WATERMARK)
        .key(store.redis_only_revocation_key(&user_id.to_string()))
        .arg(timestamp_watermark(OffsetDateTime::now_utc()))
        .invoke_async(&mut connection)
        .await?;
    Ok(())
}
