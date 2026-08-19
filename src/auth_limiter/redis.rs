use ::redis::Script;
use uuid::Uuid;

use super::domain::{
    AuthFailureLimiter, AuthFailureLimits, AuthLimiterFailurePolicy, AuthReservation,
    FailureDimension, FailureRecord, LimiterDimension, LimiterFuture,
};
use super::policy::{
    LimiterPolicy, count_failure_records, log_blocked_dimension, log_limit, value_hash,
};
use crate::{redis_keyspace::RedisKeyspace, settings::SettingsService};

const FAILURE_KEY_PREFIX: &str = "chenxing:auth:failure:";
const PENDING_KEY_PREFIX: &str = "chenxing:auth:pending:";
use super::redis_scripts::*;
use crate::redis_client::RedisClient;

#[derive(Clone)]
pub struct RedisAuthFailureLimiter {
    client: RedisClient,
    keyspace: RedisKeyspace,
    /// 阈值来源与故障处置。Redis 与 settings 两类故障都经由它分发到同一个
    /// `AuthLimiterFailurePolicy`（#300）。
    policy: LimiterPolicy,
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
            keyspace: RedisKeyspace::default(),
            policy: LimiterPolicy::fixed(failure_policy, limits),
        }
    }

    pub fn with_settings(
        client: impl Into<RedisClient>,
        failure_policy: AuthLimiterFailurePolicy,
        settings: SettingsService,
    ) -> Self {
        Self {
            client: client.into(),
            keyspace: RedisKeyspace::default(),
            policy: LimiterPolicy::from_settings(failure_policy, settings),
        }
    }

    pub fn with_settings_and_keyspace(
        client: impl Into<RedisClient>,
        failure_policy: AuthLimiterFailurePolicy,
        settings: SettingsService,
        keyspace: RedisKeyspace,
    ) -> Self {
        Self {
            client: client.into(),
            keyspace,
            policy: LimiterPolicy::from_settings(failure_policy, settings),
        }
    }

    /// 失败历史的 ZSET key。滑动窗口下这就是最终 key——不再由 Lua 追加窗口后缀。
    fn failure_key(&self, dimension: FailureDimension, value: &str) -> String {
        self.keyspace.key(&format!(
            "{FAILURE_KEY_PREFIX}{}:{}",
            dimension.as_str(),
            value_hash(value)
        ))
    }

    /// 在途预留计数器的 key。
    fn pending_key(&self, dimension: FailureDimension, value: &str) -> String {
        self.keyspace.key(&format!(
            "{PENDING_KEY_PREFIX}{}:{}",
            dimension.as_str(),
            value_hash(value)
        ))
    }

    /// ZSET member。同一次调用的多个维度共用一个 UUID，由 Lua 追加维度下标区分，
    /// 因此即使调用方重复传入同一维度也不会把两次失败折叠成一条记录。
    fn failure_member() -> String {
        Uuid::new_v4().simple().to_string()
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
    /// 滑动窗口下 key 不带窗口后缀，DEL 不需要窗口时长，因此这里不读取阈值：少一次
    /// settings 往返，也少一条「配置读不到就无法清空失败计数」的失败路径——那条路径
    /// 会在成功认证后把用户继续锁在限流里。
    fn clear<'a>(&'a self, dimension: FailureDimension, value: &str) -> LimiterFuture<'a, ()> {
        let value = value.to_owned();
        Box::pin(async move {
            let dimensions = [(dimension, value.clone())];
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.policy.unavailable_unit("clear", &dimensions),
            };
            let script = Script::new(CLEAR_FAILURE_SCRIPT);
            let mut invocation = script.prepare_invoke();
            invocation.key(self.failure_key(dimension, &value));
            let result: Result<i64, _> = invocation.invoke_async(&mut connection).await;
            if result.is_err() {
                return self.policy.unavailable_unit("clear", &dimensions);
            }
            Ok(())
        })
    }

    fn any_limited<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, bool> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(false);
            }
            let limits = self.policy.current_limits("check", &dimensions).await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.policy.unavailable_bool("check", &dimensions),
            };
            let script = Script::new(CHECK_LIMITS_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(self.failure_key(*dimension, value));
            }
            invocation.arg(limits.window());
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            // 脚本返回第一个触发上限的维度下标（1-based），0 表示没有维度触发。
            let blocked: i64 = match invocation.invoke_async(&mut connection).await {
                Ok(blocked) => blocked,
                Err(_) => return self.policy.unavailable_bool("check", &dimensions),
            };
            Ok(log_blocked_dimension(blocked, &dimensions, limits.window()))
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
            let limits = self.policy.current_limits("record", &dimensions).await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.policy.unavailable_record("record", &dimensions),
            };
            let script = Script::new(RECORD_FAILURE_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(self.failure_key(*dimension, value));
            }
            invocation.arg(limits.window());
            invocation.arg(Self::failure_member());
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            let flags: Vec<i64> = match invocation.invoke_async(&mut connection).await {
                Ok(flags) => flags,
                Err(_) => return self.policy.unavailable_record("record", &dimensions),
            };
            if flags.len() != dimensions.len() {
                return self.policy.unavailable_record("record", &dimensions);
            }
            Ok(FailureRecord::recorded(reached_dimensions(
                &dimensions,
                flags,
                limits.window(),
            )))
        })
    }

    fn reserve<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, AuthReservation> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(AuthReservation::single(dimensions, AuthReservation::token()));
            }
            let limits = self.policy.current_limits("reserve", &dimensions).await?;
            let token = AuthReservation::token();
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.policy.unavailable_reservation("reserve", &dimensions),
            };
            let script = Script::new(RESERVE_ATTEMPT_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(self.failure_key(*dimension, value));
            }
            for (dimension, value) in &dimensions {
                invocation.key(self.pending_key(*dimension, value));
            }
            invocation.arg(dimensions.len());
            invocation.arg(limits.window());
            invocation.arg(&token);
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            let blocked: i64 = match invocation.invoke_async(&mut connection).await {
                Ok(blocked) => blocked,
                Err(_) => return self.policy.unavailable_reservation("reserve", &dimensions),
            };
            if log_blocked_dimension(blocked, &dimensions, limits.window()) {
                return Ok(AuthReservation::single(Vec::new(), token));
            }
            Ok(AuthReservation::single(dimensions, token))
        })
    }

    fn record_reserved_failures<'a>(
        &'a self,
        reservation: AuthReservation,
    ) -> LimiterFuture<'a, FailureRecord> {
        Box::pin(async move {
            let dimensions = reservation.dimensions();
            if dimensions.is_empty() {
                return Ok(FailureRecord::not_recorded());
            }
            let limits = self
                .policy
                .current_limits("record_reserved", &dimensions)
                .await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => {
                    return self
                        .policy
                        .unavailable_record("record_reserved", &dimensions);
                }
            };
            let script = Script::new(RECORD_RESERVED_FAILURE_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(self.failure_key(*dimension, value));
            }
            for (dimension, value) in &dimensions {
                invocation.key(self.pending_key(*dimension, value));
            }
            invocation.arg(dimensions.len());
            invocation.arg(limits.window());
            invocation.arg(&reservation.leases[0].token);
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            let flags: Vec<i64> = match invocation.invoke_async(&mut connection).await {
                Ok(flags) => flags,
                Err(_) => {
                    return self
                        .policy
                        .unavailable_record("record_reserved", &dimensions);
                }
            };
            if flags.len() != dimensions.len() {
                return self
                    .policy
                    .unavailable_record("record_reserved", &dimensions);
            }
            Ok(FailureRecord::recorded(reached_dimensions(
                &dimensions,
                flags,
                limits.window(),
            )))
        })
    }

    /// 归还预留。与 `clear` 同理：pending key 不带窗口后缀，DECR 不需要窗口时长，
    /// 因此不读取阈值——认证已经成功，此时再因为读不到配置而失败只会把在途配额白白
    /// 挂到 TTL 过期。
    fn release<'a>(&'a self, reservation: AuthReservation) -> LimiterFuture<'a, ()> {
        Box::pin(async move {
            let dimensions = reservation.dimensions();
            if reservation.is_empty() {
                return Ok(());
            }
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.policy.unavailable_unit("release", &dimensions),
            };
            let script = Script::new(RELEASE_ATTEMPT_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(self.pending_key(*dimension, value));
            }
            invocation.arg(dimensions.len());
            invocation.arg(&reservation.leases[0].token);
            let result: Result<i64, _> = invocation.invoke_async(&mut connection).await;
            if result.is_err() {
                return self.policy.unavailable_unit("release", &dimensions);
            }
            Ok(())
        })
    }
}

/// 把脚本返回的 per-dimension 标记翻译成触发上限的维度列表，并为每个触发项打日志。
fn reached_dimensions(
    dimensions: &[LimiterDimension],
    flags: Vec<i64>,
    window_seconds: i64,
) -> Vec<FailureDimension> {
    count_failure_records(dimensions.len());
    dimensions
        .iter()
        .zip(flags)
        .filter_map(|((dimension, value), flag)| {
            if flag == 1 {
                log_limit(*dimension, value, window_seconds);
                Some(*dimension)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "redis_keyspace_tests.rs"]
mod keyspace_tests;
