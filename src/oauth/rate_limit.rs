//! 并发（QPS）限流：按 OAuth Client 的 1 秒滑动窗口计数，超限返回 429。
//! 使用 Redis ZSET + 服务端时间原子清理、写入并判定，避免固定整秒窗口
//! 在秒边界附近把并发请求拆到不同桶里。

use redis::Script;
use thiserror::Error;
use uuid::Uuid;

use crate::redis_client::RedisClient;

const QPS_SCRIPT: &str = r#"
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local member = ARGV[3]
local ttl = tonumber(ARGV[4])
local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local current = redis.call('ZCARD', key)
if current >= limit then
  redis.call('EXPIRE', key, ttl)
  return 0
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, ttl)
return 1
"#;

const QPS_WINDOW_MS: i64 = 1_000;
const QPS_KEY_TTL_SECONDS: i64 = 2;

#[derive(Clone)]
pub struct QpsRateLimiter {
    client: RedisClient,
}

#[derive(Debug, Error)]
pub enum QpsRateLimitError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("redis rate limit script returned an invalid response")]
    InvalidResponse,
}

impl QpsRateLimiter {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
        }
    }

    /// 对 `client_id` 在最近 1 秒滑动窗口内计数。返回 `true` 表示放行，
    /// `false` 表示超过 `max_qps` 应拒绝；`max_qps` 由调用方决定是否为 `None`（不启用）。
    pub async fn allow(&self, client_id: &str, max_qps: u32) -> Result<bool, QpsRateLimitError> {
        self.allow_key(format!("chenxing:qps:{client_id}"), max_qps)
            .await
    }

    /// Limit unauthenticated token attempts independently from any Client plan.
    pub async fn allow_source(
        &self,
        source_ip: &str,
        max_qps: u32,
    ) -> Result<bool, QpsRateLimitError> {
        self.allow_key(format!("chenxing:qps:source:{source_ip}"), max_qps)
            .await
    }

    async fn allow_key(&self, key: String, max_qps: u32) -> Result<bool, QpsRateLimitError> {
        let member = Uuid::new_v4().simple().to_string();
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let allowed: i64 = Script::new(QPS_SCRIPT)
            .key(key)
            .arg(QPS_WINDOW_MS)
            .arg(max_qps)
            .arg(member)
            .arg(QPS_KEY_TTL_SECONDS)
            .invoke_async(&mut connection)
            .await?;
        match allowed {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(QpsRateLimitError::InvalidResponse),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::QpsRateLimiter;

    fn limiter() -> QpsRateLimiter {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        QpsRateLimiter::new(redis::Client::open(url).expect("Redis URL"))
    }

    #[tokio::test]
    async fn sliding_window_rejects_requests_over_the_limit() {
        let limiter = limiter();
        let client_id = format!("qps-test-{}", uuid::Uuid::new_v4().simple());
        assert!(limiter.allow(&client_id, 2).await.expect("first request"));
        assert!(limiter.allow(&client_id, 2).await.expect("second request"));
        assert!(!limiter.allow(&client_id, 2).await.expect("third request"));
    }

    #[tokio::test]
    async fn concurrent_requests_share_the_same_window() {
        let limiter = limiter();
        let client_id = format!("qps-concurrent-{}", uuid::Uuid::new_v4().simple());
        let (first, second, third) = tokio::join!(
            limiter.allow(&client_id, 2),
            limiter.allow(&client_id, 2),
            limiter.allow(&client_id, 2),
        );
        let mut allowed = [
            first.expect("first concurrent request"),
            second.expect("second concurrent request"),
            third.expect("third concurrent request"),
        ];
        allowed.sort_unstable();
        assert_eq!(allowed, [false, true, true]);
    }
}
