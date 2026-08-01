use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ::redis::{AsyncCommands, Client, Script};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::domain::{
    AUTH_FAILURE_WINDOW_SECONDS, AuthFailureLimiter, AuthLimiterError, FailureDimension,
    LimiterFuture,
};

const FAILURE_KEY_PREFIX: &str = "chenxing:auth:failure:";
const RECORD_FAILURE_SCRIPT: &str = r#"
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return current
"#;

#[derive(Clone)]
pub struct RedisAuthFailureLimiter {
    client: Client,
}

impl RedisAuthFailureLimiter {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    fn window() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp() / AUTH_FAILURE_WINDOW_SECONDS
    }

    fn value_hash(value: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
    }

    fn key(dimension: FailureDimension, value: &str, window: i64) -> String {
        format!(
            "{FAILURE_KEY_PREFIX}{}:{}:{window}",
            dimension.as_str(),
            Self::value_hash(value)
        )
    }

    fn log_limit(dimension: FailureDimension, value: &str, window: i64) {
        tracing::warn!(
            dimension = dimension.as_str(),
            key_hash = %Self::value_hash(value),
            window,
            "authentication failure limit triggered"
        );
    }
}

impl AuthFailureLimiter for RedisAuthFailureLimiter {
    fn is_limited<'a>(
        &'a self,
        dimension: FailureDimension,
        value: &'a str,
    ) -> LimiterFuture<'a, bool> {
        Box::pin(async move {
            let window = Self::window();
            let key = Self::key(dimension, value, window);
            let mut connection = self
                .client
                .get_multiplexed_async_connection()
                .await
                .map_err(|_| AuthLimiterError::Storage)?;
            let count: Option<i64> = connection
                .get(key)
                .await
                .map_err(|_| AuthLimiterError::Storage)?;
            let limited = count.is_some_and(|count| count >= dimension.limit());
            if limited {
                Self::log_limit(dimension, value, window);
            }
            Ok(limited)
        })
    }

    fn record_failure<'a>(
        &'a self,
        dimension: FailureDimension,
        value: &'a str,
    ) -> LimiterFuture<'a, bool> {
        Box::pin(async move {
            let window = Self::window();
            let key = Self::key(dimension, value, window);
            let mut connection = self
                .client
                .get_multiplexed_async_connection()
                .await
                .map_err(|_| AuthLimiterError::Storage)?;
            let count: i64 = Script::new(RECORD_FAILURE_SCRIPT)
                .key(key)
                .arg(AUTH_FAILURE_WINDOW_SECONDS)
                .invoke_async(&mut connection)
                .await
                .map_err(|_| AuthLimiterError::Storage)?;
            let reached_limit = count >= dimension.limit();
            if reached_limit {
                Self::log_limit(dimension, value, window);
            }
            Ok(reached_limit)
        })
    }

    fn clear<'a>(&'a self, dimension: FailureDimension, value: &'a str) -> LimiterFuture<'a, ()> {
        Box::pin(async move {
            let key = Self::key(dimension, value, Self::window());
            let mut connection = self
                .client
                .get_multiplexed_async_connection()
                .await
                .map_err(|_| AuthLimiterError::Storage)?;
            let _: usize = connection
                .del(key)
                .await
                .map_err(|_| AuthLimiterError::Storage)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RedisAuthFailureLimiter;
    use crate::auth_limiter::{AuthFailureLimiter, FailureDimension};

    fn limiter() -> RedisAuthFailureLimiter {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        RedisAuthFailureLimiter::new(::redis::Client::open(url).expect("Redis URL"))
    }

    fn unique_value(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
    }

    #[tokio::test]
    async fn account_failures_are_rejected_after_ten_attempts() {
        let limiter = limiter();
        let account = unique_value("account");
        for attempt in 0..10 {
            assert_eq!(
                limiter
                    .record_failure(FailureDimension::Account, &account)
                    .await
                    .expect("record account failure"),
                attempt == 9
            );
        }
        assert!(
            limiter
                .is_limited(FailureDimension::Account, &account)
                .await
                .expect("check account limit")
        );
    }

    #[tokio::test]
    async fn successful_login_clears_account_failure_counter() {
        let limiter = limiter();
        let account = unique_value("account");
        limiter
            .record_failure(FailureDimension::Account, &account)
            .await
            .expect("record account failure");
        limiter
            .clear(FailureDimension::Account, &account)
            .await
            .expect("clear account failure");
        assert!(
            !limiter
                .is_limited(FailureDimension::Account, &account)
                .await
                .expect("check account limit")
        );
    }
}
