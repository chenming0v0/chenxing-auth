//! 并发（QPS）限流：按 OAuth Client 的滑动窗口计数，超限返回 429。
//! 生产窗口固定 1 秒（见 [`QpsRateLimiter::new`]）。
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

/// 生产滑动窗口长度。协议行为的一部分：套餐里的 `max_qps` 就是「每秒请求数」。
const QPS_WINDOW_MS: i64 = 1_000;

#[derive(Clone)]
pub struct QpsRateLimiter {
    client: RedisClient,
    window_ms: i64,
}

#[derive(Debug, Error)]
pub enum QpsRateLimitError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("redis rate limit script returned an invalid response")]
    InvalidResponse,
}

impl QpsRateLimiter {
    /// 生产构造器：1 秒滑动窗口。所有非测试路径都必须用这个。
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self::with_window_ms(client, QPS_WINDOW_MS)
    }

    /// 显式指定滑动窗口长度。
    ///
    /// 存在的唯一理由是让集成测试摆脱墙上时钟：token 端点在 `enforce_qps` 之前
    /// 必须先做一次 19 MiB 的 Argon2 校验（反计时预言机设计，不可绕过），
    /// 两发请求在慢机器上就可能跨出 1 秒窗口，让「第二发必被限流」变成 flake。
    /// 测试用一个足够大的窗口把「窗口内」变成确定事实。
    ///
    /// 生产必须使用 [`QpsRateLimiter::new`]：窗口长度是协议语义，不是可调参数。
    ///
    /// # Panics
    ///
    /// `window_ms <= 0` 时 panic。非正窗口会让 Lua 里的 `now - window` 清空整个
    /// ZSET，等于静默关闭限流；宁可在构造期大声炸掉，也不能悄悄放行所有请求。
    pub fn with_window_ms(client: impl Into<RedisClient>, window_ms: i64) -> Self {
        assert!(
            window_ms > 0,
            "QPS sliding window must be positive, got {window_ms}ms"
        );
        Self {
            client: client.into(),
            window_ms,
        }
    }

    /// Redis key 的 TTL，必须由窗口推导。
    ///
    /// 窗口 1000ms → 2s（与历史硬编码常量一致），60_000ms → 61s。TTL 若固定在 2s，
    /// 长窗口的 key 会先过期，窗口内的条目凭空消失，注入窗口就白做了。
    /// 多出的 1 秒是安全余量：TTL 每次写入都会刷新，只要不短于窗口就不会截断窗口。
    fn key_ttl_seconds(&self) -> i64 {
        // 有符号 div_ceil 仍是 nightly，构造期已保证 window_ms > 0，转 u64 安全。
        (self.window_ms as u64).div_ceil(1_000) as i64 + 1
    }

    /// 对 `client_id` 在最近一个滑动窗口内计数。返回 `true` 表示放行，
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
            .arg(self.window_ms)
            .arg(max_qps)
            .arg(member)
            .arg(self.key_ttl_seconds())
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
    use super::{QPS_WINDOW_MS, QpsRateLimiter};
    use redis::AsyncCommands;

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
    }

    fn limiter() -> QpsRateLimiter {
        QpsRateLimiter::new(redis::Client::open(redis_url()).expect("Redis URL"))
    }

    fn limiter_with_window(window_ms: i64) -> QpsRateLimiter {
        QpsRateLimiter::with_window_ms(
            redis::Client::open(redis_url()).expect("Redis URL"),
            window_ms,
        )
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

    /// TTL 由窗口推导，且必须复刻历史上 1000ms → 2s 的关系。
    #[test]
    fn key_ttl_is_derived_from_the_window() {
        assert_eq!(limiter().key_ttl_seconds(), 2, "production window is 1s");
        assert_eq!(limiter_with_window(QPS_WINDOW_MS).key_ttl_seconds(), 2);
        assert_eq!(limiter_with_window(1).key_ttl_seconds(), 2);
        assert_eq!(limiter_with_window(1_001).key_ttl_seconds(), 3);
        assert_eq!(limiter_with_window(2_000).key_ttl_seconds(), 3);
        assert_eq!(limiter_with_window(60_000).key_ttl_seconds(), 61);
    }

    #[test]
    #[should_panic(expected = "QPS sliding window must be positive")]
    fn non_positive_window_is_rejected() {
        // 非正窗口等于「放行一切」，必须在构造期就炸掉。
        limiter_with_window(0);
    }

    /// `new()` 保持 1 秒语义：超过一个窗口后旧条目被清掉，请求重新放行。
    #[tokio::test]
    async fn default_window_expires_after_one_second() {
        let limiter = limiter();
        let client_id = format!("qps-default-window-{}", uuid::Uuid::new_v4().simple());
        assert!(limiter.allow(&client_id, 1).await.expect("first request"));
        assert!(
            !limiter.allow(&client_id, 1).await.expect("second request"),
            "second request inside the 1s window must be rejected"
        );
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
        assert!(
            limiter.allow(&client_id, 1).await.expect("third request"),
            "1.2s later the entry left the 1s window and the request is allowed again"
        );
    }

    /// 大窗口同时验证两件事：窗口本身生效（1 秒后仍然拒绝），
    /// 以及推导出的 TTL 跟着放大（key 没在 2 秒后过期把条目带走）。
    #[tokio::test]
    async fn large_window_keeps_rejecting_after_one_second() {
        let limiter = limiter_with_window(60_000);
        let client_id = format!("qps-large-window-{}", uuid::Uuid::new_v4().simple());
        assert!(limiter.allow(&client_id, 1).await.expect("first request"));
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
        assert!(
            !limiter.allow(&client_id, 1).await.expect("second request"),
            "60s window must still count the entry recorded 1.2s ago"
        );

        let mut connection = limiter
            .client
            .get_multiplexed_async_connection()
            .await
            .expect("Redis connection");
        let ttl: i64 = connection
            .ttl(format!("chenxing:qps:{client_id}"))
            .await
            .expect("key TTL");
        assert!(
            ttl > 2,
            "key TTL must scale with the window, got {ttl}s (hardcoded 2s would evict entries)"
        );
    }
}
