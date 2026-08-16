//! 并发（QPS）限流：按 OAuth Client 的滑动窗口计数，超限返回 429。
//! 生产窗口固定 1 秒（见 [`QpsRateLimiter::new`]）。
//! 使用 Redis ZSET + 服务端时间原子清理、写入并判定，避免固定整秒窗口
//! 在秒边界附近把并发请求拆到不同桶里。

use redis::Script;
use thiserror::Error;
use uuid::Uuid;

use crate::{redis_client::RedisClient, redis_keyspace::RedisKeyspace};

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
    keyspace: RedisKeyspace,
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
        Self::with_window_ms_and_keyspace(client, QPS_WINDOW_MS, RedisKeyspace::default())
    }

    pub fn with_keyspace(client: impl Into<RedisClient>, keyspace: RedisKeyspace) -> Self {
        Self::with_window_ms_and_keyspace(client, QPS_WINDOW_MS, keyspace)
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
        Self::with_window_ms_and_keyspace(client, window_ms, RedisKeyspace::default())
    }

    pub fn with_window_ms_and_keyspace(
        client: impl Into<RedisClient>,
        window_ms: i64,
        keyspace: RedisKeyspace,
    ) -> Self {
        assert!(
            window_ms > 0,
            "QPS sliding window must be positive, got {window_ms}ms"
        );
        Self {
            client: client.into(),
            window_ms,
            keyspace,
        }
    }

    /// Redis key 的 TTL，必须由窗口推导。
    ///
    /// 窗口 1000ms → 2s（与历史硬编码常量一致），60_000ms → 61s。TTL 若固定在 2s，
    /// 长窗口的 key 会先过期，窗口内的条目凭空消失，注入窗口就白做了。
    /// 多出的 1 秒是安全余量：TTL 每次写入都会刷新，只要不短于窗口就不会截断窗口。
    fn key_ttl_seconds(window_ms: i64) -> i64 {
        // 有符号 div_ceil 仍是 nightly，调用方已保证 window_ms > 0，转 u64 安全。
        (window_ms as u64).div_ceil(1_000) as i64 + 1
    }

    /// 对 `client_id` 在最近一个滑动窗口内计数。返回 `true` 表示放行，
    /// `false` 表示超过 `max_qps` 应拒绝；`max_qps` 由调用方决定是否为 `None`（不启用）。
    pub async fn allow(&self, client_id: &str, max_qps: u32) -> Result<bool, QpsRateLimitError> {
        self.allow_key(
            self.keyspace.key(&format!("chenxing:qps:{client_id}")),
            max_qps,
            self.window_ms,
        )
        .await
    }

    /// Limit unauthenticated token attempts independently from any Client plan.
    pub async fn allow_source(
        &self,
        source_ip: &str,
        max_qps: u32,
    ) -> Result<bool, QpsRateLimitError> {
        self.allow_key(
            self.keyspace
                .key(&format!("chenxing:qps:source:{source_ip}")),
            max_qps,
            self.window_ms,
        )
        .await
    }

    /// 按调用方给定的窗口在 `scope` 维度计数，与实例的 QPS 窗口无关。
    ///
    /// 存在的理由：不是所有滥用面都以「每秒请求数」度量。Owner 引导（#279）
    /// 一个部署一生只该发生一次，合理配额是「每分钟几次」，用 1 秒窗口去限
    /// 等于不限。底层 Lua 已经是通用滑动窗口，与其为每个非 QPS 维度再写一份
    /// 脚本，不如把窗口长度提到参数位置。
    ///
    /// `scope` 必须由调用方带上自己的命名空间前缀，避免与 `chenxing:qps:*` 撞 key。
    ///
    /// # Panics
    ///
    /// `window_ms <= 0` 时 panic，理由同 [`QpsRateLimiter::with_window_ms`]：
    /// 非正窗口会清空整个 ZSET，等于静默放行。
    pub async fn allow_scoped(
        &self,
        scope: &str,
        limit: u32,
        window_ms: i64,
    ) -> Result<bool, QpsRateLimitError> {
        assert!(
            window_ms > 0,
            "scoped sliding window must be positive, got {window_ms}ms"
        );
        self.allow_key(self.keyspace.key(scope), limit, window_ms)
            .await
    }

    async fn allow_key(
        &self,
        key: String,
        max_qps: u32,
        window_ms: i64,
    ) -> Result<bool, QpsRateLimitError> {
        let member = Uuid::new_v4().simple().to_string();
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let allowed: i64 = Script::new(QPS_SCRIPT)
            .key(key)
            .arg(window_ms)
            .arg(max_qps)
            .arg(member)
            .arg(Self::key_ttl_seconds(window_ms))
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

    fn limiter_with_window(window_ms: i64) -> QpsRateLimiter {
        QpsRateLimiter::with_window_ms(
            redis::Client::open("redis://127.0.0.1:1").expect("Redis URL"),
            window_ms,
        )
    }

    /// TTL 由窗口推导，且必须复刻历史上 1000ms → 2s 的关系。
    #[test]
    fn key_ttl_is_derived_from_the_window() {
        assert_eq!(
            QpsRateLimiter::key_ttl_seconds(QPS_WINDOW_MS),
            2,
            "production window is 1s"
        );
        assert_eq!(QpsRateLimiter::key_ttl_seconds(1), 2);
        assert_eq!(QpsRateLimiter::key_ttl_seconds(1_001), 3);
        assert_eq!(QpsRateLimiter::key_ttl_seconds(2_000), 3);
        assert_eq!(QpsRateLimiter::key_ttl_seconds(60_000), 61);
    }

    #[tokio::test]
    #[should_panic(expected = "scoped sliding window must be positive")]
    async fn non_positive_scoped_window_is_rejected() {
        let _ = limiter_with_window(QPS_WINDOW_MS)
            .allow_scoped("chenxing:test:scoped:invalid", 1, 0)
            .await;
    }

    #[test]
    #[should_panic(expected = "QPS sliding window must be positive")]
    fn non_positive_window_is_rejected() {
        // 非正窗口等于「放行一切」，必须在构造期就炸掉。
        limiter_with_window(0);
    }
}
