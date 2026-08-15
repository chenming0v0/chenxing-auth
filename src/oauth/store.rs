use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{AsyncCommands, Script};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::code::AuthorizationCode;
use super::quota::QuotaRefundCancel;
use crate::{clock::SharedClock, redis_client::RedisClient, redis_keyspace::RedisKeyspace};

#[derive(Clone)]
pub struct AuthorizationCodeStore {
    client: RedisClient,
    clock: SharedClock,
    keyspace: RedisKeyspace,
}

#[derive(Debug, Error)]
pub enum AuthorizationCodeStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("authorization code serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl AuthorizationCodeStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
            clock: SharedClock::system(),
            keyspace: RedisKeyspace::default(),
        }
    }

    pub fn with_keyspace(client: impl Into<RedisClient>, keyspace: RedisKeyspace) -> Self {
        Self {
            client: client.into(),
            clock: SharedClock::system(),
            keyspace,
        }
    }

    /// 注入共享时钟（`AppState` 构造时调用，测试用固定时钟驱动 TTL 边界）。
    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

    pub async fn save(&self, code: &AuthorizationCode) -> Result<(), AuthorizationCodeStoreError> {
        // TTL 来自授权码本身的 expires_at，与配置的 security_limits.authorization_code_ttl_seconds
        // 保持一致（#121）。remaining_seconds 不足1时强制设为1而不是0（Redis 不接受0）。
        let remaining = (code.expires_at - self.clock.now()).whole_seconds();
        let ttl = if remaining > 0 { remaining as u64 } else { 1 };
        self.save_with_ttl(code, ttl).await
    }

    pub async fn restore(
        &self,
        code: &AuthorizationCode,
        ttl_seconds: u64,
    ) -> Result<(), AuthorizationCodeStoreError> {
        self.save_with_ttl(code, ttl_seconds).await
    }

    async fn save_with_ttl(
        &self,
        code: &AuthorizationCode,
        ttl_seconds: u64,
    ) -> Result<(), AuthorizationCodeStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(code)?;
        let _: () = connection
            .set_ex(self.key(&code.value), payload, ttl_seconds.max(1))
            .await?;
        Ok(())
    }

    pub async fn take(
        &self,
        value: &str,
    ) -> Result<Option<AuthorizationCode>, AuthorizationCodeStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get_del(self.key(value)).await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationCodeStoreError::from)
    }

    pub async fn find(
        &self,
        value: &str,
    ) -> Result<Option<AuthorizationCode>, AuthorizationCodeStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(self.key(value)).await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationCodeStoreError::from)
    }

    pub async fn take_if_matches(
        &self,
        value: &str,
        code: &AuthorizationCode,
    ) -> Result<bool, AuthorizationCodeStoreError> {
        self.take_if_matches_with_quota_cancel(value, code, None)
            .await
    }

    /// 原子消费授权码（CAS），并在同一个 Lua 事务里取消关联的待退配额条目。
    ///
    /// 兑换成功时配额必须保留（计数保留是正确行为），因此取消待退条目必须与
    /// 授权码的删除原子完成：分成两步会让后台退款 worker 有机会在两步之间
    /// 看到条目，把「已兑换」的配额退掉（Issue #341）。
    ///
    /// `quota_cancel = None`（授权码没有计量配额，或兑换旧格式在途授权码）时
    /// 行为与 [`Self::take_if_matches`] 完全一致。
    pub async fn take_if_matches_with_quota_cancel(
        &self,
        value: &str,
        code: &AuthorizationCode,
        quota_cancel: Option<QuotaRefundCancel>,
    ) -> Result<bool, AuthorizationCodeStoreError> {
        let expected = serde_json::to_string(code)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        // 没有待退条目时 KEYS[2] 用授权码键占位（脚本在 ARGV[2] 为空时不会
        // 引用它），member 传空串即退化为纯 CAS。
        let code_key = self.key(value);
        let zset_key: &str = quota_cancel
            .as_ref()
            .map(|cancel| cancel.zset_key.as_str())
            .unwrap_or(&code_key);
        let member = quota_cancel
            .as_ref()
            .map(|cancel| cancel.member.as_str())
            .unwrap_or("");
        let deleted: i32 = Script::new(
            r#"local current_json = redis.call('GET', KEYS[1])
               if not current_json then
                    return 0
               end
               local current = cjson.decode(current_json)
               local expected = cjson.decode(ARGV[1])
               local fields = {
                   'value', 'client_id', 'redirect_uri', 'user_id',
                   'session_token_hash', 'quota_reservation_id', 'scopes',
                   'code_challenge', 'nonce', 'created_at', 'expires_at', 'redeemed_at'
               }
               local function encoded(value)
                   if value == nil then return 'null' end
                   return cjson.encode(value)
               end
               for _, field in ipairs(fields) do
                   if encoded(current[field]) ~= encoded(expected[field]) then
                       return 0
                   end
               end
               redis.call('DEL', KEYS[1])
               if ARGV[2] ~= '' then
                   redis.call('ZREM', KEYS[2], ARGV[2])
               end
               return 1"#,
        )
        .key(code_key.as_str())
        .key(zset_key)
        .arg(expected)
        .arg(member)
        .invoke_async(&mut connection)
        .await?;
        Ok(deleted == 1)
    }

    fn key(&self, value: &str) -> String {
        self.keyspace.key(&format!(
            "chenxing:oauth:code:{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
        ))
    }
}
