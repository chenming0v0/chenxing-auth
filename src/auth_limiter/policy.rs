use std::sync::atomic::{AtomicU64, Ordering};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use super::domain::{
    AuthFailureLimits, AuthLimiterError, AuthLimiterFailurePolicy, FailureDimension, FailureRecord,
    LimiterDimension,
};
use crate::settings::{SecurityLimitsSetting, SettingsService};

static REDIS_ERRORS: AtomicU64 = AtomicU64::new(0);
static SETTINGS_ERRORS: AtomicU64 = AtomicU64::new(0);
static LIMIT_HITS: AtomicU64 = AtomicU64::new(0);
static FAILURE_RECORDS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthLimiterMetrics {
    pub redis_errors: u64,
    /// 阈值读取降级次数（#300）。与 `redis_errors` 分开计数：两者的处置动作相同，
    /// 但根因完全不同——混在一起会让运维把 settings 数据库故障误判为 Redis 故障。
    pub settings_errors: u64,
    pub limit_hits: u64,
    pub failure_records: u64,
}

pub fn metrics() -> AuthLimiterMetrics {
    AuthLimiterMetrics {
        redis_errors: REDIS_ERRORS.load(Ordering::Relaxed),
        settings_errors: SETTINGS_ERRORS.load(Ordering::Relaxed),
        limit_hits: LIMIT_HITS.load(Ordering::Relaxed),
        failure_records: FAILURE_RECORDS.load(Ordering::Relaxed),
    }
}

pub(crate) fn count_failure_records(count: usize) {
    FAILURE_RECORDS.fetch_add(count as u64, Ordering::Relaxed);
}

/// 限流维度取值的稳定哈希。日志与 Redis key 都只使用它，不落原始账号或 IP。
pub(crate) fn value_hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

/// 记录限流命中。`window_seconds` 是滑动窗口时长；固定窗口时代这里打的是
/// epoch 桶号，滑动窗口下桶号不存在，时长才是有意义的诊断信息。
pub(crate) fn log_limit(dimension: FailureDimension, value: &str, window_seconds: i64) {
    LIMIT_HITS.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(
        event = "auth_limiter.limit_reached",
        dimension = dimension.as_str(),
        key_hash = %value_hash(value),
        window_seconds,
        "authentication failure limit triggered"
    );
}

/// 只给真正触发上限的那个维度打日志。
///
/// `blocked` 是脚本返回的 1-based 维度下标，0 表示没有维度触发。此前这里对全部
/// 维度统一打日志：一次因源 IP 超限被拒的请求会同时记下「账户维度已达上限」，
/// 运维排查时看到的是假象。
pub(crate) fn log_blocked_dimension(
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
        log_limit(*dimension, value, window_seconds);
    }
    true
}

impl From<&SecurityLimitsSetting> for AuthFailureLimits {
    fn from(value: &SecurityLimitsSetting) -> Self {
        Self {
            window_seconds: value.auth_failure_window_seconds,
            account_limit: value.account_failure_limit,
            ip_limit: value.ip_failure_limit,
            ticket_limit: value.totp_ticket_failure_limit,
        }
    }
}

/// 限流器的阈值来源与故障处置策略。
///
/// 把两件事放在一起是因为它们在每个操作里成对出现：先拿到阈值，再在存储不可用时
/// 按同一个 `AuthLimiterFailurePolicy` 决定放行还是拒绝。#300 之前阈值读取失败绕过了
/// 这个分发，直接 `?` 返回 `Storage`，于是 fail-open 部署在 settings 数据库故障时
/// 依然全站认证 500。
#[derive(Clone)]
pub(crate) struct LimiterPolicy {
    failure_policy: AuthLimiterFailurePolicy,
    /// 没有配置 `SettingsService` 时使用的固定阈值（测试与静态配置部署）。
    /// 配置了 `SettingsService` 时降级取值由缓存给出，不经过这个字段。
    fallback_limits: AuthFailureLimits,
    settings: Option<SettingsService>,
}

impl LimiterPolicy {
    pub(crate) fn fixed(
        failure_policy: AuthLimiterFailurePolicy,
        fallback_limits: AuthFailureLimits,
    ) -> Self {
        Self {
            failure_policy,
            fallback_limits,
            settings: None,
        }
    }

    pub(crate) fn from_settings(
        failure_policy: AuthLimiterFailurePolicy,
        settings: SettingsService,
    ) -> Self {
        Self {
            failure_policy,
            fallback_limits: AuthFailureLimits::default(),
            settings: Some(settings),
        }
    }

    /// 取当前阈值。
    ///
    /// 稳态下命中 `SettingsService` 的进程内缓存，不查询 `app_settings`。读取失败时
    /// 缓存给出最后已知安全值或启动期默认值，本方法据此走故障策略：
    ///
    /// - fail-open：带着降级阈值继续限流。阈值仍然生效，只是可能陈旧；认证不返回 500。
    /// - fail-closed：拒绝并返回 `Storage`，与 Redis 不可用时的处置一致。
    pub(crate) async fn current_limits(
        &self,
        operation: &str,
        dimensions: &[LimiterDimension],
    ) -> Result<AuthFailureLimits, AuthLimiterError> {
        let Some(settings) = &self.settings else {
            return Ok(self.fallback_limits);
        };
        let cached = settings.cached_security_limits().await;
        let limits = AuthFailureLimits::from(&cached.value);
        if !cached.is_degraded() {
            return Ok(limits);
        }
        SETTINGS_ERRORS.fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            event = "auth_limiter.settings_unavailable",
            operation,
            dimension = first_dimension(dimensions),
            dimensions = dimensions.len(),
            policy = self.failure_policy.as_str(),
            limits_source = cached.source.as_str(),
            window_seconds = limits.window(),
            "authentication limiter could not refresh security limits"
        );
        match self.failure_policy {
            AuthLimiterFailurePolicy::FailOpen => Ok(limits),
            AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
        }
    }

    fn log_storage_error(&self, operation: &str, dimensions: &[LimiterDimension]) {
        REDIS_ERRORS.fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            event = "auth_limiter.redis_unavailable",
            operation,
            dimension = first_dimension(dimensions),
            dimensions = dimensions.len(),
            policy = self.failure_policy.as_str(),
            "authentication limiter storage operation failed"
        );
    }

    pub(crate) fn unavailable_bool(
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

    pub(crate) fn unavailable_record(
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

    pub(crate) fn unavailable_reservation(
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

    /// `clear` 与 `release` 的处置：两者都没有返回值，fail-open 下静默降级。
    pub(crate) fn unavailable_unit(
        &self,
        operation: &str,
        dimensions: &[LimiterDimension],
    ) -> Result<(), AuthLimiterError> {
        self.log_storage_error(operation, dimensions);
        match self.failure_policy {
            AuthLimiterFailurePolicy::FailOpen => Ok(()),
            AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
        }
    }
}

fn first_dimension(dimensions: &[LimiterDimension]) -> &'static str {
    dimensions
        .first()
        .map_or("none", |(dimension, _)| dimension.as_str())
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
