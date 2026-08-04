use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{Client, Script};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

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
}

#[derive(Clone)]
pub struct ExternalLoginStateStore {
    client: Client,
    prefix: String,
    source_rate_limit: i64,
    max_pending: i64,
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
    #[error("redis state admission script returned an invalid response")]
    InvalidResponse,
}

impl ExternalLoginStateStore {
    pub fn new(client: Client) -> Self {
        Self::new_with_limits(
            client,
            STATE_KEY_PREFIX.to_owned(),
            EXTERNAL_LOGIN_STATE_RATE_LIMIT,
            EXTERNAL_LOGIN_STATE_MAX_PENDING,
        )
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
        let payload = serde_json::to_string(value)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let result: i64 = Script::new(SAVE_STATE_SCRIPT)
            .key(self.pending_key())
            .key(self.rate_key(source_ip))
            .key(self.state_key(&value.state))
            .arg(EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS)
            .arg(self.source_rate_limit)
            .arg(self.max_pending)
            .arg(EXTERNAL_LOGIN_STATE_TTL_SECONDS)
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
        client: Client,
        prefix: String,
        source_rate_limit: i64,
        max_pending: i64,
    ) -> Self {
        Self {
            client,
            prefix,
            source_rate_limit,
            max_pending,
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
    use std::sync::Arc;

    use redis::AsyncCommands;
    use uuid::Uuid;

    use super::{ExternalLoginState, ExternalLoginStateStore, ExternalLoginStateStoreError};

    fn redis_client() -> redis::Client {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        redis::Client::open(url).expect("Redis URL")
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
        let store = ExternalLoginStateStore::new_with_limits(client.clone(), prefix, 2, 10);
        for index in 0..2 {
            store
                .save_from_source(
                    &ExternalLoginState {
                        state: format!("state-{index}"),
                        provider_slug: "example".to_owned(),
                        request_id: None,
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
