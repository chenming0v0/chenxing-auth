use std::{
    sync::RwLock,
    time::{Duration, Instant},
};

use super::SecurityLimitsSetting;

/// 稳态下认证限流不再每次查询 `app_settings` 的缓存 TTL（#300）。
///
/// 取 5 秒而不是分钟级：管理员在设置页保存阈值后，处理该请求的实例会主动刷新缓存，
/// 但多实例部署里其他实例只能靠 TTL 收敛。5 秒既让每个认证动作在稳态下零数据库
/// 往返，又把「阈值已改、某实例仍按旧值限流」的窗口压到运维可接受的范围。
pub const SECURITY_LIMITS_CACHE_TTL: Duration = Duration::from_secs(5);

/// 读取失败后到下一次重试之间的最小间隔。
///
/// 没有这个退避，settings 数据库故障期间每个认证请求都会在 TTL 过期后各自发起一次
/// 查询——正好在数据库已经不健康时叠加满负载重试。退避期内直接返回最后已知值并标记
/// 为降级，故障策略语义不变，数据库压力有界。
pub const SECURITY_LIMITS_ERROR_BACKOFF: Duration = Duration::from_secs(1);

/// 一份已校验阈值的来源。调用方据此决定是否走故障策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLimitsSource {
    /// 命中未过期的内存缓存，本次没有查询数据库。
    Cache,
    /// 本次成功查询了数据库，缓存已更新。
    Loaded,
    /// 数据库读取失败，使用上一次成功加载的值。
    LastKnown,
    /// 数据库读取失败且从未成功加载过，使用启动期默认值（来自环境变量配置）。
    StartupDefault,
}

impl SecurityLimitsSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Loaded => "loaded",
            Self::LastKnown => "last_known",
            Self::StartupDefault => "startup_default",
        }
    }

    /// 是否处于降级状态，即本次取值背后有一次失败的 settings 读取。
    pub const fn is_degraded(self) -> bool {
        matches!(self, Self::LastKnown | Self::StartupDefault)
    }
}

/// 一次取值的结果：阈值本身，加上它的来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedSecurityLimits {
    pub value: SecurityLimitsSetting,
    pub source: SecurityLimitsSource,
}

impl CachedSecurityLimits {
    pub const fn is_degraded(&self) -> bool {
        self.source.is_degraded()
    }
}

#[derive(Debug)]
struct CacheState {
    /// 最后已知的安全值。初值是启动期默认值，因此永远存在可用阈值。
    value: SecurityLimitsSetting,
    /// 最后一次成功加载的时刻。`None` 表示 `value` 仍是启动期默认值。
    loaded_at: Option<Instant>,
    /// 最后一次读取失败的时刻，用于退避。
    failed_at: Option<Instant>,
}

/// 已校验 `SecurityLimitsSetting` 的进程内缓存。
///
/// 由 `SettingsService` 持有并随其 `Clone` 共享（`Arc` 在服务侧），所以管理接口写入后
/// 主动刷新对同一进程内的全部读取路径立即生效。
#[derive(Debug)]
pub struct SecurityLimitsCache {
    state: RwLock<CacheState>,
    ttl: Duration,
    error_backoff: Duration,
}

impl SecurityLimitsCache {
    pub fn new(startup_default: SecurityLimitsSetting) -> Self {
        Self::with_durations(
            startup_default,
            SECURITY_LIMITS_CACHE_TTL,
            SECURITY_LIMITS_ERROR_BACKOFF,
        )
    }

    pub fn with_durations(
        startup_default: SecurityLimitsSetting,
        ttl: Duration,
        error_backoff: Duration,
    ) -> Self {
        Self {
            state: RwLock::new(CacheState {
                value: startup_default,
                loaded_at: None,
                failed_at: None,
            }),
            ttl,
            error_backoff,
        }
    }

    /// 命中未过期缓存时返回阈值，否则返回 `None` 表示调用方需要加载。
    pub fn fresh(&self) -> Option<SecurityLimitsSetting> {
        let state = self.read();
        let loaded_at = state.loaded_at?;
        (loaded_at.elapsed() < self.ttl).then(|| state.value.clone())
    }

    /// 读取失败后的退避判定：仍在退避窗口内时给出应当直接使用的降级取值。
    pub fn backoff_fallback(&self) -> Option<CachedSecurityLimits> {
        let state = self.read();
        let failed_at = state.failed_at?;
        (failed_at.elapsed() < self.error_backoff).then(|| CachedSecurityLimits {
            value: state.value.clone(),
            source: Self::degraded_source(state.loaded_at),
        })
    }

    /// 记录一次成功加载。清除失败标记，让下一次故障重新走完整重试路径。
    pub fn store(&self, value: SecurityLimitsSetting) {
        let mut state = self.write();
        state.value = value;
        state.loaded_at = Some(Instant::now());
        state.failed_at = None;
    }

    /// 记录一次失败加载，并给出应当使用的最后已知安全值或启动期默认值。
    pub fn record_failure(&self) -> CachedSecurityLimits {
        let mut state = self.write();
        state.failed_at = Some(Instant::now());
        CachedSecurityLimits {
            value: state.value.clone(),
            source: Self::degraded_source(state.loaded_at),
        }
    }

    const fn degraded_source(loaded_at: Option<Instant>) -> SecurityLimitsSource {
        if loaded_at.is_some() {
            SecurityLimitsSource::LastKnown
        } else {
            SecurityLimitsSource::StartupDefault
        }
    }

    /// 锁中毒只可能来自持锁期间的 panic。写入是整体替换一份已校验的值，不存在被写坏
    /// 一半的中间状态，继续使用它比让全站认证陷入 panic 更符合可用性目标。
    /// 这与 `keys.rs` 的 `read_state` / `write_state` 采用同一处置。
    fn read(&self) -> std::sync::RwLockReadGuard<'_, CacheState> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, CacheState> {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tightened() -> SecurityLimitsSetting {
        SecurityLimitsSetting {
            account_failure_limit: 3,
            ..SecurityLimitsSetting::default()
        }
    }

    #[test]
    fn new_cache_reports_no_fresh_value_until_a_successful_load() {
        let cache = SecurityLimitsCache::new(SecurityLimitsSetting::default());
        assert_eq!(cache.fresh(), None);
        cache.store(tightened());
        assert_eq!(cache.fresh(), Some(tightened()));
    }

    #[test]
    fn expired_entries_force_a_reload() {
        let cache = SecurityLimitsCache::with_durations(
            SecurityLimitsSetting::default(),
            Duration::ZERO,
            Duration::ZERO,
        );
        cache.store(tightened());
        assert_eq!(
            cache.fresh(),
            None,
            "a zero TTL must never serve a cached value"
        );
    }

    /// 从未成功加载过时的降级取值必须是启动期默认值，而不是空。
    #[test]
    fn failure_without_any_successful_load_falls_back_to_the_startup_default() {
        let startup = tightened();
        let cache = SecurityLimitsCache::new(startup.clone());
        let fallback = cache.record_failure();
        assert_eq!(fallback.value, startup);
        assert_eq!(fallback.source, SecurityLimitsSource::StartupDefault);
        assert!(fallback.is_degraded());
    }

    /// 成功加载过之后的降级取值必须是最后已知值，而不是退回启动期默认。
    #[test]
    fn failure_after_a_successful_load_falls_back_to_the_last_known_value() {
        let cache = SecurityLimitsCache::new(SecurityLimitsSetting::default());
        cache.store(tightened());
        let fallback = cache.record_failure();
        assert_eq!(fallback.value, tightened());
        assert_eq!(fallback.source, SecurityLimitsSource::LastKnown);
    }

    /// 退避窗口内不再查询数据库：故障期间的重试压力必须有界。
    #[test]
    fn failures_are_backed_off_before_the_next_load_attempt() {
        let cache = SecurityLimitsCache::with_durations(
            SecurityLimitsSetting::default(),
            Duration::ZERO,
            Duration::from_secs(60),
        );
        assert!(
            cache.backoff_fallback().is_none(),
            "no failure has been recorded yet"
        );
        cache.record_failure();
        let backed_off = cache
            .backoff_fallback()
            .expect("a recent failure must be backed off");
        assert_eq!(backed_off.source, SecurityLimitsSource::StartupDefault);
    }

    /// 退避窗口为 0 时每次都重试，用于测试与「立即恢复」语义。
    #[test]
    fn zero_backoff_retries_immediately() {
        let cache = SecurityLimitsCache::with_durations(
            SecurityLimitsSetting::default(),
            Duration::ZERO,
            Duration::ZERO,
        );
        cache.record_failure();
        assert!(cache.backoff_fallback().is_none());
    }

    /// 一次成功加载必须清掉失败标记，否则故障恢复后仍会被退避挡住。
    #[test]
    fn a_successful_load_clears_the_failure_backoff() {
        let cache = SecurityLimitsCache::with_durations(
            SecurityLimitsSetting::default(),
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        cache.record_failure();
        assert!(cache.backoff_fallback().is_some());
        cache.store(tightened());
        assert!(cache.backoff_fallback().is_none());
        assert_eq!(cache.fresh(), Some(tightened()));
    }

    #[test]
    fn only_failure_sources_are_degraded() {
        assert!(!SecurityLimitsSource::Cache.is_degraded());
        assert!(!SecurityLimitsSource::Loaded.is_degraded());
        assert!(SecurityLimitsSource::LastKnown.is_degraded());
        assert!(SecurityLimitsSource::StartupDefault.is_degraded());
        assert_eq!(SecurityLimitsSource::Cache.as_str(), "cache");
        assert_eq!(SecurityLimitsSource::Loaded.as_str(), "loaded");
        assert_eq!(SecurityLimitsSource::LastKnown.as_str(), "last_known");
        assert_eq!(
            SecurityLimitsSource::StartupDefault.as_str(),
            "startup_default"
        );
    }
}
