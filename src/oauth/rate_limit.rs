//! 并发（QPS）限流：按 OAuth Client 的 1 秒固定窗口计数，超限返回 429。
//! 使用 Redis 脚本原子执行 INCR + 首次设置 TTL，避免并发下重复过期。

use redis::Client;
use thiserror::Error;
use time::OffsetDateTime;

const QPS_SCRIPT: &str = r#"
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
if current > tonumber(ARGV[1]) then return 0 end
return 1
"#;

#[derive(Clone)]
pub struct QpsRateLimiter {
    client: Client,
}

#[derive(Debug, Error)]
pub enum QpsRateLimitError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("redis rate limit script returned an invalid response")]
    InvalidResponse,
}

impl QpsRateLimiter {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// 对 `client_id` 在当前秒窗口内计数。返回 `true` 表示放行，
    /// `false` 表示超过 `max_qps` 应拒绝；`max_qps` 由调用方决定是否为 `None`（不启用）。
    pub async fn allow(&self, client_id: &str, max_qps: u32) -> Result<bool, QpsRateLimitError> {
        let window = OffsetDateTime::now_utc().unix_timestamp();
        let key = format!("chenxing:qps:{client_id}:{window}");
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let allowed: i64 = redis::Script::new(QPS_SCRIPT)
            .key(key)
            .arg(max_qps)
            .arg(2)
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
    async fn fixed_window_rejects_requests_over_the_limit() {
        let limiter = limiter();
        let client_id = format!("qps-test-{}", uuid::Uuid::new_v4().simple());
        assert!(limiter.allow(&client_id, 2).await.expect("first request"));
        assert!(limiter.allow(&client_id, 2).await.expect("second request"));
        assert!(!limiter.allow(&client_id, 2).await.expect("third request"));
    }
}
