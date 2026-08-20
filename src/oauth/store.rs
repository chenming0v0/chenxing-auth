use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{AsyncCommands, Script};
use sha2::{Digest, Sha256};
#[cfg(debug_assertions)]
use std::{
    collections::HashSet,
    sync::{Mutex, OnceLock},
};
use thiserror::Error;

use super::code::AuthorizationCode;
use super::quota::{QuotaRefundCancel, refund_due_unix_millis};
use crate::{clock::SharedClock, redis_client::RedisClient, redis_keyspace::RedisKeyspace};

#[cfg(debug_assertions)]
fn restore_failures_for_tests() -> &'static Mutex<HashSet<String>> {
    static FAILURES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    FAILURES.get_or_init(|| Mutex::new(HashSet::new()))
}

#[cfg(debug_assertions)]
fn take_restore_failure_for_test(code_value: &str) -> bool {
    restore_failures_for_tests()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(code_value)
}

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

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn fail_restore_with_quota_refund_once_for_tests(&self, code_value: &str) {
        restore_failures_for_tests()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(code_value.to_owned());
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

    /// Restore a consumed authorization code and its pending quota refund in
    /// one Redis transaction. The code TTL is supplied in milliseconds so a
    /// retry cannot gain more lifetime than remained at compensation time.
    pub async fn restore_with_quota_refund(
        &self,
        code: &AuthorizationCode,
        remaining_ttl_ms: u64,
        quota_cancel: Option<QuotaRefundCancel>,
    ) -> Result<(), AuthorizationCodeStoreError> {
        let payload = serde_json::to_string(code)?;
        #[cfg(debug_assertions)]
        if take_restore_failure_for_test(&code.value) {
            return Err(redis::RedisError::from((
                redis::ErrorKind::IoError,
                "injected authorization-code restore failure",
            ))
            .into());
        }
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let code_key = self.key(&code.value);
        let (refund_key, record_key, reservation_id, refund_score) = quota_cancel
            .as_ref()
            .map(|cancel| {
                (
                    cancel.zset_key.clone(),
                    cancel.record_key.clone(),
                    cancel.member.clone(),
                    refund_due_unix_millis(code.expires_at) as f64,
                )
            })
            .unwrap_or_else(|| (code_key.clone(), code_key.clone(), String::new(), 0.0));
        let ttl_ms = i64::try_from(remaining_ttl_ms).unwrap_or(i64::MAX);
        let _: i64 = Script::new(super::quota_scripts::RESTORE_CODE_AND_QUOTA_SCRIPT)
            .key(code_key)
            .key(refund_key)
            .key(record_key)
            .arg(payload)
            .arg(ttl_ms)
            .arg(reservation_id)
            .arg(refund_score)
            .invoke_async(&mut connection)
            .await?;
        Ok(())
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

    /// 原子消费授权码（CAS），并在同一个 Lua 事务里占用关联的配额 reservation。
    ///
    /// CAS 身份是 `value` + `cas_revision`，不比较完整 JSON。未来字段和
    /// 已知协议字段的序列化布局变化都不会让有效授权码消费失败。
    ///
    /// 兑换成功时配额必须保留。周期 hash 是这次 INCR 的一次性 claim：CAS
    /// 先 HDEL 且不 DECR，退款脚本随后 HDEL 只能空操作。待退 ZSET 成员也在
    /// 同一事务里 ZREM，避免 worker 把已兑换的配额退掉（Issue #341 / #657）。
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
        // 没有待退条目时 KEYS[2]/KEYS[3] 用授权码键占位（脚本在 ARGV[2] 为空
        // 时不会引用它们），member 传空串即退化为纯 CAS。
        let code_key = self.key(value);
        let zset_key: &str = quota_cancel
            .as_ref()
            .map(|cancel| cancel.zset_key.as_str())
            .unwrap_or(&code_key);
        let record_key: &str = quota_cancel
            .as_ref()
            .map(|cancel| cancel.record_key.as_str())
            .unwrap_or(&code_key);
        let member = quota_cancel
            .as_ref()
            .map(|cancel| cancel.member.as_str())
            .unwrap_or("");
        let deleted: i32 = Script::new(concat!(
            super::cas::cas_identity_lua!(),
            super::quota_scripts::take_code_and_claim_quota_lua!(),
        ))
        .key(code_key.as_str())
        .key(zset_key)
        .key(record_key)
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
