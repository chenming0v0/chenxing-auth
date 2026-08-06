use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::Script;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    redis_client::RedisClient,
    settings::{SecurityLimitsSetting, SettingsService, SettingsServiceError},
};

/// 外部 OAuth 登录 state 的默认有效期（秒）。运行时优先使用管理设置或启动配置覆盖。
pub const EXTERNAL_LOGIN_STATE_TTL_SECONDS: u64 = 600;
pub const EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS: u64 = 60;
pub const EXTERNAL_LOGIN_STATE_RATE_LIMIT: i64 = 30;
pub const EXTERNAL_LOGIN_STATE_MAX_PENDING: i64 = 10_000;

const STATE_KEY_PREFIX: &str = "chenxing:oauth:external-state";
const SAVE_STATE_SCRIPT: &str = r#"
local pending_key = KEYS[1]
local rate_key = KEYS[2]
local state_key = KEYS[3]
local window_seconds = tonumber(ARGV[1])
local rate_limit = tonumber(ARGV[2])
local pending_limit = tonumber(ARGV[3])
local ttl_seconds = tonumber(ARGV[4])
local state = ARGV[5]
local payload = ARGV[6]
local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)

redis.call('ZREMRANGEBYSCORE', pending_key, '-inf', now)
redis.call('ZREMRANGEBYSCORE', rate_key, '-inf', now - (window_seconds * 1000))
if redis.call('ZCARD', rate_key) >= rate_limit then return 0 end
if redis.call('ZCARD', pending_key) >= pending_limit then return -1 end
if not redis.call('SET', state_key, payload, 'EX', ttl_seconds, 'NX') then return -2 end

redis.call('ZADD', pending_key, now + (ttl_seconds * 1000), state)
redis.call('ZADD', rate_key, now, state)
redis.call('EXPIRE', pending_key, ttl_seconds + 1)
redis.call('EXPIRE', rate_key, window_seconds + 1)
return 1
"#;

const TAKE_STATE_SCRIPT: &str = r#"
local payload = redis.call('GET', KEYS[1])
if payload then
    redis.call('DEL', KEYS[1])
    redis.call('ZREM', KEYS[2], ARGV[1])
end
return payload
"#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalLoginState {
    pub state: String,
    pub provider_slug: String,
    pub request_id: Option<String>,
    /// 发往外部 IdP 的 PKCE `code_verifier`（RFC 7636 §4.1）。
    ///
    /// **一次性凭据，禁止写入日志。** 该结构体不派生 `Display`，且不得整体传入
    /// `tracing` 宏；需要记录上下文时只记录 `state` 与 `provider_slug`。
    ///
    /// `#[serde(default)]` 是升级兼容契约：滚动升级期间 Redis 里已存在的旧 state
    /// payload 没有该字段，缺失时反序列化为空串而不是整体失败，否则所有进行中的
    /// 外部登录都会被打断。空串表示「本次登录未使用 PKCE」，`exchange_code`
    /// 会相应地不发送 `code_verifier`。
    #[serde(default)]
    pub code_verifier: String,
}

#[derive(Clone)]
pub struct ExternalLoginStateStore {
    client: RedisClient,
    prefix: String,
    source_rate_limit: i64,
    max_pending: i64,
    /// Standalone-store fallback TTL; production reads the setting service per admission.
    ttl_seconds: u64,
    /// Standalone-store fallback rate window; production reads the setting service per admission.
    rate_window_seconds: u64,
    settings: Option<SettingsService>,
}

#[derive(Debug, Error)]
pub enum ExternalLoginStateStoreError {
    #[error("external OAuth state source rate limit was exceeded")]
    RateLimited,
    #[error("external OAuth pending state capacity was exhausted")]
    CapacityExceeded,
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("state serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("security limits setting operation failed: {0}")]
    Settings(#[from] SettingsServiceError),
    #[error("redis state admission script returned an invalid response")]
    InvalidResponse,
}

impl ExternalLoginStateStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self::new_with_limits(
            client,
            STATE_KEY_PREFIX.to_owned(),
            EXTERNAL_LOGIN_STATE_RATE_LIMIT,
            EXTERNAL_LOGIN_STATE_MAX_PENDING,
            EXTERNAL_LOGIN_STATE_TTL_SECONDS,
            EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS,
        )
    }

    /// 构造带运行期配置的实例（#121）。
    pub fn new_with_config(
        client: impl Into<RedisClient>,
        ttl_seconds: u64,
        rate_window_seconds: u64,
        rate_limit: i64,
        max_pending: i64,
    ) -> Self {
        Self::new_with_limits(
            client,
            STATE_KEY_PREFIX.to_owned(),
            rate_limit,
            max_pending,
            ttl_seconds,
            rate_window_seconds,
        )
    }

    pub fn new_with_settings(
        client: impl Into<RedisClient>,
        settings: SettingsService,
    ) -> Self {
        let mut store = Self::new_with_limits(
            client,
            STATE_KEY_PREFIX.to_owned(),
            EXTERNAL_LOGIN_STATE_RATE_LIMIT,
            EXTERNAL_LOGIN_STATE_MAX_PENDING,
            EXTERNAL_LOGIN_STATE_TTL_SECONDS,
            EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS,
        );
        store.settings = Some(settings);
        store
    }

    pub async fn save(
        &self,
        value: &ExternalLoginState,
    ) -> Result<(), ExternalLoginStateStoreError> {
        self.save_from_source(value, "unknown").await
    }

    pub async fn save_from_source(
        &self,
        value: &ExternalLoginState,
        source_ip: &str,
    ) -> Result<(), ExternalLoginStateStoreError> {
        let limits = self.current_limits().await?;
        self.save_from_source_with_limits(value, source_ip, &limits)
            .await
    }

    pub(crate) async fn save_from_source_with_limits(
        &self,
        value: &ExternalLoginState,
        source_ip: &str,
        limits: &SecurityLimitsSetting,
    ) -> Result<(), ExternalLoginStateStoreError> {
        let payload = serde_json::to_string(value)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let result: i64 = Script::new(SAVE_STATE_SCRIPT)
            .key(self.pending_key())
            .key(self.rate_key(source_ip))
            .key(self.state_key(&value.state))
            .arg(limits.external_login_state_rate_window_seconds)
            .arg(limits.external_login_state_rate_limit)
            .arg(limits.external_login_state_max_pending)
            .arg(limits.external_login_state_ttl_seconds)
            .arg(&value.state)
            .arg(payload)
            .invoke_async(&mut connection)
            .await?;
        match result {
            1 => Ok(()),
            0 => Err(ExternalLoginStateStoreError::RateLimited),
            -1 => Err(ExternalLoginStateStoreError::CapacityExceeded),
            _ => Err(ExternalLoginStateStoreError::InvalidResponse),
        }
    }

    pub async fn take(
        &self,
        state: &str,
    ) -> Result<Option<ExternalLoginState>, ExternalLoginStateStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = Script::new(TAKE_STATE_SCRIPT)
            .key(self.state_key(state))
            .key(self.pending_key())
            .arg(state)
            .invoke_async(&mut connection)
            .await?;
        payload
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(Into::into)
    }

    fn new_with_limits(
        client: impl Into<RedisClient>,
        prefix: String,
        source_rate_limit: i64,
        max_pending: i64,
        ttl_seconds: u64,
        rate_window_seconds: u64,
    ) -> Self {
        Self {
            client: client.into(),
            prefix,
            source_rate_limit,
            max_pending,
            ttl_seconds,
            rate_window_seconds,
            settings: None,
        }
    }

    async fn current_limits(&self) -> Result<SecurityLimitsSetting, ExternalLoginStateStoreError> {
        match &self.settings {
            Some(settings) => Ok(settings.security_limits().await?),
            None => {
                let mut limits = SecurityLimitsSetting::default();
                limits.external_login_state_rate_limit = self.source_rate_limit;
                limits.external_login_state_max_pending = self.max_pending;
                limits.external_login_state_ttl_seconds = self.ttl_seconds;
                limits.external_login_state_rate_window_seconds = self.rate_window_seconds;
                Ok(limits)
            }
        }
    }

    fn pending_key(&self) -> String {
        format!("{}:pending", self.prefix)
    }

    fn rate_key(&self, source_ip: &str) -> String {
        let source_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(source_ip.as_bytes()));
        format!("{}:rate:{source_hash}", self.prefix)
    }

    fn state_key(&self, state: &str) -> String {
        format!("{}:{state}", self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::{EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS, EXTERNAL_LOGIN_STATE_TTL_SECONDS};
    use std::sync::Arc;

    use redis::AsyncCommands;
    use uuid::Uuid;

    use super::{ExternalLoginState, ExternalLoginStateStore, ExternalLoginStateStoreError};

    fn redis_client() -> redis::Client {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        redis::Client::open(url).expect("Redis URL")
    }

    /// 兼容性回归：滚动升级期间 Redis 里的旧 payload 没有 `code_verifier` 字段，
    /// 必须能反序列化为空串，否则所有进行中的外部登录都会失败。
    #[test]
    fn legacy_state_without_code_verifier_deserializes() {
        let legacy = r#"{"state":"legacy-state","provider_slug":"example","request_id":null}"#;
        let restored: ExternalLoginState =
            serde_json::from_str(legacy).expect("旧 payload 必须仍可反序列化");
        assert_eq!(restored.state, "legacy-state");
        assert_eq!(restored.provider_slug, "example");
        assert_eq!(restored.request_id, None);
        assert_eq!(
            restored.code_verifier, "",
            "缺失的 code_verifier 应回退为空串（表示本次登录未使用 PKCE）"
        );
    }

    #[test]
    fn state_with_code_verifier_round_trips() {
        let original = ExternalLoginState {
            state: "state-value".to_owned(),
            provider_slug: "example".to_owned(),
            request_id: Some("request-value".to_owned()),
            code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned(),
        };
        let payload = serde_json::to_string(&original).expect("序列化");
        let restored: ExternalLoginState = serde_json::from_str(&payload).expect("反序列化");
        assert_eq!(restored, original);
    }

    #[tokio::test]
    async fn concurrent_admission_never_exceeds_pending_capacity() {
        let client = redis_client();
        let prefix = format!("chenxing:test:external-state:{}", Uuid::new_v4().simple());
        let store = Arc::new(ExternalLoginStateStore::new_with_limits(
            client.clone(),
            prefix,
            100,
            4,
            EXTERNAL_LOGIN_STATE_TTL_SECONDS,
            EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS,
        ));
        let source_ip = "198.51.100.7";
        let mut tasks = Vec::new();
        for index in 0..32 {
            let store = Arc::clone(&store);
            tasks.push(tokio::spawn(async move {
                store
                    .save_from_source(
                        &ExternalLoginState {
                            state: format!("state-{index}"),
                            provider_slug: "example".to_owned(),
                            request_id: None,
                            code_verifier: String::new(),
                        },
                        source_ip,
                    )
                    .await
            }));
        }

        let mut admitted = 0;
        for task in tasks {
            if task.await.expect("admission task").is_ok() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 4);

        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("Redis connection");
        let _: usize = connection
            .del(store.pending_key())
            .await
            .expect("pending cleanup");
        let _: usize = connection
            .del(store.rate_key(source_ip))
            .await
            .expect("rate cleanup");
    }

    #[tokio::test]
    async fn source_rate_limit_rejects_without_creating_an_extra_state() {
        let client = redis_client();
        let prefix = format!("chenxing:test:external-state:{}", Uuid::new_v4().simple());
        let store = ExternalLoginStateStore::new_with_limits(
            client.clone(),
            prefix,
            2,
            10,
            EXTERNAL_LOGIN_STATE_TTL_SECONDS,
            EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS,
        );
        for index in 0..2 {
            store
                .save_from_source(
                    &ExternalLoginState {
                        state: format!("state-{index}"),
                        provider_slug: "example".to_owned(),
                        request_id: None,
                        code_verifier: String::new(),
                    },
                    "198.51.100.8",
                )
                .await
                .expect("state admission");
        }
        assert!(matches!(
            store
                .save_from_source(
                    &ExternalLoginState {
                        state: "state-third".to_owned(),
                        provider_slug: "example".to_owned(),
                        request_id: None,
                        code_verifier: String::new(),
                    },
                    "198.51.100.8",
                )
                .await,
            Err(ExternalLoginStateStoreError::RateLimited)
        ));

        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("Redis connection");
        let _: usize = connection
            .del(store.pending_key())
            .await
            .expect("pending cleanup");
        let _: usize = connection
            .del(store.rate_key("198.51.100.8"))
            .await
            .expect("rate cleanup");
    }
}
