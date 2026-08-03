use ::redis::{AsyncCommands, Client, Script};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;

use super::domain::{
    AUTH_FAILURE_WINDOW_SECONDS, AuthFailureLimiter, AuthLimiterError, AuthLimiterFailurePolicy,
    FailureDimension, FailureRecord, LimiterDimension, LimiterFuture,
};

const FAILURE_KEY_PREFIX: &str = "chenxing:auth:failure:";
const CHECK_LIMITS_SCRIPT: &str = r#"
for index, key in ipairs(KEYS) do
    local current = redis.call('GET', key)
    if current and tonumber(current) >= tonumber(ARGV[index]) then
        return 1
    end
end
return 0
"#;
const RECORD_FAILURE_SCRIPT: &str = r#"
local reached = {}
for index, key in ipairs(KEYS) do
    local limit = tonumber(ARGV[index + 1])
    local current = tonumber(redis.call('GET', key) or '0')
    if current < limit then
        current = redis.call('INCR', key)
        if current == 1 then redis.call('EXPIRE', key, ARGV[1]) end
    end
    if current >= limit then
        reached[index] = 1
    else
        reached[index] = 0
    end
end
return reached
"#;

static REDIS_ERRORS: AtomicU64 = AtomicU64::new(0);
static LIMIT_HITS: AtomicU64 = AtomicU64::new(0);
static FAILURE_RECORDS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthLimiterMetrics {
    pub redis_errors: u64,
    pub limit_hits: u64,
    pub failure_records: u64,
}

pub fn metrics() -> AuthLimiterMetrics {
    AuthLimiterMetrics {
        redis_errors: REDIS_ERRORS.load(Ordering::Relaxed),
        limit_hits: LIMIT_HITS.load(Ordering::Relaxed),
        failure_records: FAILURE_RECORDS.load(Ordering::Relaxed),
    }
}

#[derive(Clone)]
pub struct RedisAuthFailureLimiter {
    client: Client,
    failure_policy: AuthLimiterFailurePolicy,
}

impl RedisAuthFailureLimiter {
    pub fn new(client: Client) -> Self {
        Self::with_failure_policy(client, AuthLimiterFailurePolicy::FailClosed)
    }

    pub fn with_failure_policy(client: Client, failure_policy: AuthLimiterFailurePolicy) -> Self {
        Self {
            client,
            failure_policy,
        }
    }

    fn window() -> (i64, i64) {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let window = now / AUTH_FAILURE_WINDOW_SECONDS;
        let ttl = ((window + 1) * AUTH_FAILURE_WINDOW_SECONDS - now).max(1);
        (window, ttl)
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
        LIMIT_HITS.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            event = "auth_limiter.limit_reached",
            dimension = dimension.as_str(),
            key_hash = %Self::value_hash(value),
            window,
            "authentication failure limit triggered"
        );
    }

    fn log_storage_error(&self, operation: &str, dimensions: &[LimiterDimension]) {
        REDIS_ERRORS.fetch_add(1, Ordering::Relaxed);
        let dimension = dimensions
            .first()
            .map_or("none", |(dimension, _)| dimension.as_str());
        tracing::error!(
            event = "auth_limiter.redis_unavailable",
            operation,
            dimension,
            dimensions = dimensions.len(),
            policy = self.failure_policy.as_str(),
            "authentication limiter storage operation failed"
        );
    }

    fn unavailable_bool(
        &self,
        operation: &str,
        dimensions: &[LimiterDimension],
    ) -> Result<bool, AuthLimiterError> {
        self.log_storage_error(operation, dimensions);
        match self.failure_policy {
            AuthLimiterFailurePolicy::FailOpen => Ok(false),
            AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
        }
    }

    fn unavailable_record(
        &self,
        operation: &str,
        dimensions: &[LimiterDimension],
    ) -> Result<FailureRecord, AuthLimiterError> {
        self.log_storage_error(operation, dimensions);
        match self.failure_policy {
            AuthLimiterFailurePolicy::FailOpen => Ok(FailureRecord {
                reached: Vec::new(),
            }),
            AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
        }
    }
}

impl AuthFailureLimiter for RedisAuthFailureLimiter {
    fn is_limited<'a>(
        &'a self,
        dimension: FailureDimension,
        value: &str,
    ) -> LimiterFuture<'a, bool> {
        let value = value.to_owned();
        Box::pin(async move { self.any_limited(vec![(dimension, value)]).await })
    }

    fn record_failure<'a>(
        &'a self,
        dimension: FailureDimension,
        value: &str,
    ) -> LimiterFuture<'a, bool> {
        let value = value.to_owned();
        Box::pin(async move {
            let record = self.record_failures(vec![(dimension, value)]).await?;
            Ok(record.reached(dimension))
        })
    }

    fn clear<'a>(&'a self, dimension: FailureDimension, value: &str) -> LimiterFuture<'a, ()> {
        let value = value.to_owned();
        Box::pin(async move {
            let (window, _) = Self::window();
            let key = Self::key(dimension, &value, window);
            let dimensions = [(dimension, value.clone())];
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => {
                    self.log_storage_error("clear", &dimensions);
                    return match self.failure_policy {
                        AuthLimiterFailurePolicy::FailOpen => Ok(()),
                        AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
                    };
                }
            };
            if connection.del::<_, usize>(key).await.is_err() {
                self.log_storage_error("clear", &dimensions);
                if matches!(self.failure_policy, AuthLimiterFailurePolicy::FailClosed) {
                    return Err(AuthLimiterError::Storage);
                }
            }
            Ok(())
        })
    }

    fn any_limited<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, bool> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(false);
            }
            let (window, _) = Self::window();
            let keys: Vec<String> = dimensions
                .iter()
                .map(|(dimension, value)| Self::key(*dimension, value, window))
                .collect();
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.unavailable_bool("check", &dimensions),
            };
            let script = Script::new(CHECK_LIMITS_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for key in keys {
                invocation.key(key);
            }
            for (dimension, _) in &dimensions {
                invocation.arg(dimension.limit());
            }
            let limited: i64 = match invocation.invoke_async(&mut connection).await {
                Ok(limited) => limited,
                Err(_) => return self.unavailable_bool("check", &dimensions),
            };
            if limited == 1 {
                for (dimension, value) in &dimensions {
                    Self::log_limit(*dimension, value, window);
                }
            }
            Ok(limited == 1)
        })
    }

    fn record_failures<'a>(
        &'a self,
        dimensions: Vec<LimiterDimension>,
    ) -> LimiterFuture<'a, FailureRecord> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(FailureRecord {
                    reached: Vec::new(),
                });
            }
            let (window, ttl) = Self::window();
            let keys: Vec<String> = dimensions
                .iter()
                .map(|(dimension, value)| Self::key(*dimension, value, window))
                .collect();
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.unavailable_record("record", &dimensions),
            };
            let script = Script::new(RECORD_FAILURE_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for key in keys {
                invocation.key(key);
            }
            invocation.arg(ttl);
            for (dimension, _) in &dimensions {
                invocation.arg(dimension.limit());
            }
            let flags: Vec<i64> = match invocation.invoke_async(&mut connection).await {
                Ok(flags) => flags,
                Err(_) => return self.unavailable_record("record", &dimensions),
            };
            FAILURE_RECORDS.fetch_add(dimensions.len() as u64, Ordering::Relaxed);
            let reached = dimensions
                .iter()
                .zip(flags)
                .filter_map(|((dimension, value), flag)| {
                    if flag == 1 {
                        Self::log_limit(*dimension, value, window);
                        Some(*dimension)
                    } else {
                        None
                    }
                })
                .collect();
            Ok(FailureRecord { reached })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ::redis::AsyncCommands;

    use super::RedisAuthFailureLimiter;
    use crate::auth_limiter::{AuthFailureLimiter, AuthLimiterFailurePolicy, FailureDimension};

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

    #[tokio::test]
    async fn concurrent_account_failures_have_one_atomic_threshold_boundary() {
        let limiter = Arc::new(limiter());
        let account = unique_value("concurrent-account");
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let limiter = limiter.clone();
            let account = account.clone();
            tasks.push(tokio::spawn(async move {
                limiter
                    .record_failure(FailureDimension::Account, &account)
                    .await
                    .expect("record concurrent failure")
            }));
        }
        let mut reached = 0;
        for task in tasks {
            reached += u8::from(task.await.expect("join concurrent failure"));
        }
        assert_eq!(reached, 1);
    }

    #[tokio::test]
    async fn batch_failure_uses_account_ticket_and_ip_dimensions_with_window_ttl() {
        let limiter = limiter();
        let account = unique_value("batch-account");
        let ticket = unique_value("batch-ticket");
        let source_ip = unique_value("batch-ip");
        for _ in 0..4 {
            let record = limiter
                .record_failures(vec![
                    (FailureDimension::Account, account.clone()),
                    (FailureDimension::Ticket, ticket.clone()),
                    (FailureDimension::SourceIp, source_ip.clone()),
                ])
                .await
                .expect("record batch failure");
            assert!(record.reached.is_empty());
        }
        let record = limiter
            .record_failures(vec![
                (FailureDimension::Account, account.clone()),
                (FailureDimension::Ticket, ticket.clone()),
                (FailureDimension::SourceIp, source_ip.clone()),
            ])
            .await
            .expect("record threshold batch failure");
        assert!(record.reached(FailureDimension::Ticket));
        assert!(!record.reached(FailureDimension::Account));
        assert!(!record.reached(FailureDimension::SourceIp));

        let (window, _) = RedisAuthFailureLimiter::window();
        let key = RedisAuthFailureLimiter::key(FailureDimension::Ticket, &ticket, window);
        let mut connection = limiter
            .client
            .get_multiplexed_async_connection()
            .await
            .expect("Redis connection");
        let ttl: i64 = connection.ttl(key).await.expect("failure counter TTL");
        assert!(ttl > 0);
        assert!(ttl <= super::AUTH_FAILURE_WINDOW_SECONDS);
    }

    #[tokio::test]
    async fn redis_failure_policy_is_explicit_and_observable() {
        let client = ::redis::Client::open("redis://127.0.0.1:1/").expect("Redis URL");
        let fail_open = RedisAuthFailureLimiter::with_failure_policy(
            client.clone(),
            AuthLimiterFailurePolicy::FailOpen,
        );
        let fail_closed = RedisAuthFailureLimiter::with_failure_policy(
            client,
            AuthLimiterFailurePolicy::FailClosed,
        );
        let before = super::metrics().redis_errors;
        assert!(
            !fail_open
                .is_limited(FailureDimension::Account, "failure-policy-open")
                .await
                .expect("fail-open check")
        );
        assert!(
            !fail_open
                .record_failure(FailureDimension::Account, "failure-policy-open")
                .await
                .expect("fail-open record")
        );
        assert!(
            fail_closed
                .is_limited(FailureDimension::Account, "failure-policy-closed")
                .await
                .is_err()
        );
        assert!(
            fail_closed
                .record_failure(FailureDimension::Account, "failure-policy-closed")
                .await
                .is_err()
        );
        assert!(super::metrics().redis_errors >= before + 4);
    }
}
