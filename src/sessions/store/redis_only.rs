//! 纯 Redis 会话路径（未配置 Postgres 元数据时使用）。
//!
//! 这条路径没有权威记录可查，撤销只能靠"撤销水位"表达：把撤销时刻写进
//! `revoked-before:{user_id}`，此后所有 `created_at` 不晚于该时刻的会话一律判为无效。
//! 因此写入和判定都必须与水位比较，且比较要在 Redis 侧原子完成——
//! 先读水位再写会话的两步实现会让并发撤销和登录互相穿越。

use std::time::Duration;

use redis::{AsyncCommands, Script};
use time::OffsetDateTime;

use super::{SessionStore, SessionStoreError, timestamp_watermark};
use crate::{
    sessions::domain::{Session, SessionPayload},
    users::domain::UserId,
};

/// 写入会话前先比对撤销水位：水位不早于会话创建时刻则拒绝写入（返回 0）。
/// 判定与写入在同一个 Lua 脚本里完成，保证原子性。
const REDIS_ONLY_SESSION_SET: &str = "local marker = redis.call('GET', KEYS[1])\nif marker and tonumber(marker) >= tonumber(ARGV[1]) then return 0 end\nredis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])\nreturn 1";
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
    let stored: i64 = Script::new(REDIS_ONLY_SESSION_SET)
        .key(store.redis_only_revocation_key(&session.user_id))
        .key(store.key(&session.token))
        .arg(created_at)
        .arg(payload)
        .arg(ttl.as_secs().max(1))
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
    let session = stored_payload.into_session(token.to_owned());
    let marker: Option<String> = connection
        .get(store.redis_only_revocation_key(&session.user_id))
        .await?;
    // 水位判定用 `<=`：与撤销时刻同一纳秒创建的会话也必须失效，
    // 否则撤销与登录在同一时刻竞争时会漏放一条会话。
    if marker
        .and_then(|value| value.parse::<i128>().ok())
        .is_some_and(|before| session.created_at.unix_timestamp_nanos() <= before)
    {
        return Ok(None);
    }
    Ok(Some(session))
}

pub(super) async fn revoke_redis_only(
    store: &SessionStore,
    hash: &[u8],
) -> Result<(), SessionStoreError> {
    let mut connection = store.client.get_multiplexed_async_connection().await?;
    let _: usize = connection.del(store.key_hash(hash)).await?;
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
