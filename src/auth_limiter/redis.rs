use ::redis::Script;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

use super::domain::{
    AuthFailureLimiter, AuthFailureLimits, AuthLimiterError, AuthLimiterFailurePolicy,
    FailureDimension, FailureRecord, LimiterDimension, LimiterFuture,
};
use crate::settings::SettingsService;

const FAILURE_KEY_PREFIX: &str = "chenxing:auth:failure:";
const PENDING_KEY_PREFIX: &str = "chenxing:auth:pending:";
use super::redis_scripts::*;
use crate::redis_client::RedisClient;

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
    client: RedisClient,
    failure_policy: AuthLimiterFailurePolicy,
    limits: AuthFailureLimits,
    settings: Option<SettingsService>,
}

impl RedisAuthFailureLimiter {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self::with_failure_policy(client, AuthLimiterFailurePolicy::FailClosed)
    }

    pub fn with_failure_policy(
        client: impl Into<RedisClient>,
        failure_policy: AuthLimiterFailurePolicy,
    ) -> Self {
        Self::with_limits(client, failure_policy, AuthFailureLimits::default())
    }

    pub fn with_limits(
        client: impl Into<RedisClient>,
        failure_policy: AuthLimiterFailurePolicy,
        limits: AuthFailureLimits,
    ) -> Self {
        Self {
            client: client.into(),
            failure_policy,
            limits,
            settings: None,
        }
    }

    pub fn with_settings(
        client: impl Into<RedisClient>,
        failure_policy: AuthLimiterFailurePolicy,
        settings: SettingsService,
    ) -> Self {
        Self {
            client: client.into(),
            failure_policy,
            limits: AuthFailureLimits::default(),
            settings: Some(settings),
        }
    }

    async fn current_limits(&self) -> Result<AuthFailureLimits, AuthLimiterError> {
        let Some(settings) = &self.settings else {
            return Ok(self.limits);
        };
        let value = settings.security_limits().await.map_err(|error_value| {
            tracing::error!(
                error = %error_value,
                "failed to load security limits for authentication limiter"
            );
            AuthLimiterError::Storage
        })?;
        Ok(AuthFailureLimits {
            window_seconds: value.auth_failure_window_seconds,
            account_limit: value.account_failure_limit,
            ip_limit: value.ip_failure_limit,
            ticket_limit: value.totp_ticket_failure_limit,
        })
    }

    fn value_hash(value: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
    }

    /// 失败历史的 ZSET key。滑动窗口下这就是最终 key——不再由 Lua 追加窗口后缀。
    fn failure_key(dimension: FailureDimension, value: &str) -> String {
        format!(
            "{FAILURE_KEY_PREFIX}{}:{}",
            dimension.as_str(),
            Self::value_hash(value)
        )
    }

    /// 在途预留计数器的 key。
    fn pending_key(dimension: FailureDimension, value: &str) -> String {
        format!(
            "{PENDING_KEY_PREFIX}{}:{}",
            dimension.as_str(),
            Self::value_hash(value)
        )
    }

    /// ZSET member。同一次调用的多个维度共用一个 UUID，由 Lua 追加维度下标区分，
    /// 因此即使调用方重复传入同一维度也不会把两次失败折叠成一条记录。
    fn failure_member() -> String {
        Uuid::new_v4().simple().to_string()
    }

    /// 记录限流命中。`window_seconds` 是滑动窗口时长；固定窗口时代这里打的是
    /// epoch 桶号，滑动窗口下桶号不存在，时长才是有意义的诊断信息。
    fn log_limit(dimension: FailureDimension, value: &str, window_seconds: i64) {
        LIMIT_HITS.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            event = "auth_limiter.limit_reached",
            dimension = dimension.as_str(),
            key_hash = %Self::value_hash(value),
            window_seconds,
            "authentication failure limit triggered"
        );
    }

    /// 只给真正触发上限的那个维度打日志。
    ///
    /// `blocked` 是脚本返回的 1-based 维度下标，0 表示没有维度触发。此前这里对全部
    /// 维度统一打日志：一次因源 IP 超限被拒的请求会同时记下「账户维度已达上限」，
    /// 运维排查时看到的是假象。
    fn log_blocked_dimension(
        blocked: i64,
        dimensions: &[LimiterDimension],
        window_seconds: i64,
    ) -> bool {
        let Some(index) = usize::try_from(blocked).ok().and_then(|one_based| {
            // 0 表示没有维度触发；下标越界只可能来自脚本与调用方失配，按未触发处理。
            one_based.checked_sub(1)
        }) else {
            return false;
        };
        if let Some((dimension, value)) = dimensions.get(index) {
            Self::log_limit(*dimension, value, window_seconds);
        }
        true
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
            AuthLimiterFailurePolicy::FailOpen => Ok(FailureRecord::not_recorded()),
            AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
        }
    }

    fn unavailable_reservation(
        &self,
        operation: &str,
        dimensions: &[LimiterDimension],
    ) -> Result<bool, AuthLimiterError> {
        self.log_storage_error(operation, dimensions);
        match self.failure_policy {
            AuthLimiterFailurePolicy::FailOpen => Ok(true),
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

    /// 清空一个维度的失败历史。
    ///
    /// 滑动窗口下 key 不带窗口后缀，DEL 不需要窗口时长，因此这里不再读取
    /// `current_limits()`：少一次 settings 往返，也少一条「配置读不到就无法清空
    /// 失败计数」的失败路径——那条路径会在成功认证后把用户继续锁在限流里。
    fn clear<'a>(&'a self, dimension: FailureDimension, value: &str) -> LimiterFuture<'a, ()> {
        let value = value.to_owned();
        Box::pin(async move {
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
            let script = Script::new(CLEAR_FAILURE_SCRIPT);
            let mut invocation = script.prepare_invoke();
            invocation.key(Self::failure_key(dimension, &value));
            let result: Result<i64, _> = invocation.invoke_async(&mut connection).await;
            if result.is_err() {
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
            let limits = self.current_limits().await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.unavailable_bool("check", &dimensions),
            };
            let script = Script::new(CHECK_LIMITS_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(Self::failure_key(*dimension, value));
            }
            invocation.arg(limits.window());
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            // 脚本返回第一个触发上限的维度下标（1-based），0 表示没有维度触发。
            let blocked: i64 = match invocation.invoke_async(&mut connection).await {
                Ok(blocked) => blocked,
                Err(_) => return self.unavailable_bool("check", &dimensions),
            };
            Ok(Self::log_blocked_dimension(
                blocked,
                &dimensions,
                limits.window(),
            ))
        })
    }

    fn record_failures<'a>(
        &'a self,
        dimensions: Vec<LimiterDimension>,
    ) -> LimiterFuture<'a, FailureRecord> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(FailureRecord::recorded(Vec::new()));
            }
            let limits = self.current_limits().await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.unavailable_record("record", &dimensions),
            };
            let script = Script::new(RECORD_FAILURE_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(Self::failure_key(*dimension, value));
            }
            invocation.arg(limits.window());
            invocation.arg(Self::failure_member());
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            let flags: Vec<i64> = match invocation.invoke_async(&mut connection).await {
                Ok(flags) => flags,
                Err(_) => return self.unavailable_record("record", &dimensions),
            };
            if flags.len() != dimensions.len() {
                return self.unavailable_record("record", &dimensions);
            }
            FAILURE_RECORDS.fetch_add(dimensions.len() as u64, Ordering::Relaxed);
            let reached = dimensions
                .iter()
                .zip(flags)
                .filter_map(|((dimension, value), flag)| {
                    if flag == 1 {
                        Self::log_limit(*dimension, value, limits.window());
                        Some(*dimension)
                    } else {
                        None
                    }
                })
                .collect();
            Ok(FailureRecord::recorded(reached))
        })
    }

    fn reserve<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, bool> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(true);
            }
            let limits = self.current_limits().await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.unavailable_reservation("reserve", &dimensions),
            };
            let script = Script::new(RESERVE_ATTEMPT_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(Self::failure_key(*dimension, value));
            }
            for (dimension, value) in &dimensions {
                invocation.key(Self::pending_key(*dimension, value));
            }
            invocation.arg(dimensions.len());
            invocation.arg(limits.window());
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            // 与 check 共用约定：返回第一个触发上限的维度下标（1-based），0 表示预留成功。
            let blocked: i64 = match invocation.invoke_async(&mut connection).await {
                Ok(blocked) => blocked,
                Err(_) => return self.unavailable_reservation("reserve", &dimensions),
            };
            Ok(!Self::log_blocked_dimension(
                blocked,
                &dimensions,
                limits.window(),
            ))
        })
    }

    fn record_reserved_failures<'a>(
        &'a self,
        dimensions: Vec<LimiterDimension>,
    ) -> LimiterFuture<'a, FailureRecord> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(FailureRecord::recorded(Vec::new()));
            }
            let limits = self.current_limits().await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.unavailable_record("record_reserved", &dimensions),
            };
            let script = Script::new(RECORD_RESERVED_FAILURE_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(Self::failure_key(*dimension, value));
            }
            for (dimension, value) in &dimensions {
                invocation.key(Self::pending_key(*dimension, value));
            }
            invocation.arg(dimensions.len());
            invocation.arg(limits.window());
            invocation.arg(Self::failure_member());
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            let flags: Vec<i64> = match invocation.invoke_async(&mut connection).await {
                Ok(flags) => flags,
                Err(_) => return self.unavailable_record("record_reserved", &dimensions),
            };
            if flags.len() != dimensions.len() {
                return self.unavailable_record("record_reserved", &dimensions);
            }
            FAILURE_RECORDS.fetch_add(dimensions.len() as u64, Ordering::Relaxed);
            let reached = dimensions
                .iter()
                .zip(flags)
                .filter_map(|((dimension, value), flag)| {
                    if flag == 1 {
                        Self::log_limit(*dimension, value, limits.window());
                        Some(*dimension)
                    } else {
                        None
                    }
                })
                .collect();
            Ok(FailureRecord::recorded(reached))
        })
    }

    /// 归还预留。与 `clear` 同理：pending key 不带窗口后缀，DECR 不需要窗口时长，
    /// 因此不再读取 `current_limits()`——认证已经成功，此时再因为读不到配置而失败
    /// 只会把在途配额白白挂到 TTL 过期。
    fn release<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, ()> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(());
            }
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => {
                    self.log_storage_error("release", &dimensions);
                    return match self.failure_policy {
                        AuthLimiterFailurePolicy::FailOpen => Ok(()),
                        AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
                    };
                }
            };
            let script = Script::new(RELEASE_ATTEMPT_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(Self::pending_key(*dimension, value));
            }
            let result: Result<i64, _> = invocation.invoke_async(&mut connection).await;
            if result.is_err() {
                self.log_storage_error("release", &dimensions);
                if matches!(self.failure_policy, AuthLimiterFailurePolicy::FailClosed) {
                    return Err(AuthLimiterError::Storage);
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "redis_tests.rs"]
mod tests;
