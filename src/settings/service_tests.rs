//! SettingsService 的单元测试。
//!
//! 覆盖注册发件人邮箱规范化（Issue #302）、Unicode 域名 punycode 转换，
//! 以及 SecurityLimits 缓存的降级与回退语义（#300）。

use std::{sync::Arc, time::Duration};

use super::{
    SecurityLimitsCache, SecurityLimitsSetting, SecurityLimitsSource, SettingsService,
    extract_email, normalize_email,
};
use crate::oauth::providers::secrets::SecretManager;

impl SettingsService {
    /// 用自定义 TTL / 退避的缓存替换默认缓存。仅用于测试缓存与降级路径。
    pub(crate) fn with_security_limits_cache(mut self, cache: SecurityLimitsCache) -> Self {
        self.security_limits_cache = Arc::new(cache);
        self
    }

    /// 构造一个 settings 读取必然失败的服务：连接池指向不可达地址，
    /// `connect_lazy` 不在构造时连接，第一次查询才失败。
    ///
    /// 用于验证阈值读取故障时的降级取值与 `AuthLimiterFailurePolicy` 分发（#300），
    /// 不需要真实 PostgreSQL。`acquire_timeout` 必须显式压到 100ms：默认 30 秒会让
    /// 每个降级用例干等半分钟。
    pub(crate) fn unreachable_for_tests(default_security_limits: SecurityLimitsSetting) -> Self {
        let pool = crate::sqlx::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        Self::with_security_limits(
            pool,
            SecretManager::from_key([0_u8; 32]),
            "localhost",
            "http://localhost",
            default_security_limits,
        )
    }
}

fn tightened() -> SecurityLimitsSetting {
    SecurityLimitsSetting {
        account_failure_limit: 3,
        ..SecurityLimitsSetting::default()
    }
}

#[test]
fn normalizes_and_clears_registration_sender_email() {
    // 展示值保留本地部分大小写，域名统一成 IDNA ASCII 小写（Issue #302）。
    assert_eq!(
        normalize_email(Some("  Sender@Example.COM ".to_owned())).unwrap(),
        Some("Sender@example.com".to_owned())
    );
    assert_eq!(normalize_email(Some("  ".to_owned())).unwrap(), None);
    assert!(normalize_email(Some("invalid".to_owned())).is_err());
}

/// #300 的核心断言：命中缓存的读取不查询 `app_settings`。
///
/// 连接池指向不可达地址，任何一次查询都会返回 `Database`。因此两次读取都成功
/// 就证明它们都由缓存服务，没有产生数据库往返。
#[tokio::test]
async fn cached_security_limits_are_served_without_touching_the_database() {
    let cache = SecurityLimitsCache::with_durations(
        SecurityLimitsSetting::default(),
        Duration::from_secs(60),
        Duration::from_secs(60),
    );
    cache.store(tightened());
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default())
        .with_security_limits_cache(cache);

    assert_eq!(
        settings
            .security_limits()
            .await
            .expect("a fresh cache entry must not query the database"),
        tightened()
    );
    let cached = settings.cached_security_limits().await;
    assert_eq!(cached.value, tightened());
    assert_eq!(cached.source, SecurityLimitsSource::Cache);
    assert!(!cached.is_degraded());
}

/// 缓存为空且数据库不可用时，热路径读取必须给出启动期默认值并标记降级，
/// 而不是把错误抛给认证流程。
#[tokio::test]
async fn cached_security_limits_fall_back_to_the_startup_default_on_failure() {
    let settings = SettingsService::unreachable_for_tests(tightened());
    let cached = settings.cached_security_limits().await;
    assert_eq!(cached.value, tightened());
    assert_eq!(cached.source, SecurityLimitsSource::StartupDefault);
    assert!(cached.is_degraded());
}

/// 曾经成功加载过之后，故障期间必须用最后已知值，而不是退回启动期默认。
#[tokio::test]
async fn cached_security_limits_fall_back_to_the_last_known_value_on_failure() {
    let cache = SecurityLimitsCache::with_durations(
        SecurityLimitsSetting::default(),
        Duration::ZERO,
        Duration::ZERO,
    );
    cache.store(tightened());
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default())
        .with_security_limits_cache(cache);

    let cached = settings.cached_security_limits().await;
    assert_eq!(cached.value, tightened());
    assert_eq!(cached.source, SecurityLimitsSource::LastKnown);
    assert!(cached.is_degraded());
}

/// 严格读取路径（管理接口、OAuth）语义不变：缓存未命中且数据库故障仍返回错误。
#[tokio::test]
async fn strict_security_limits_still_report_database_failures() {
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default());
    assert!(settings.security_limits().await.is_err());
}

#[test]
fn normalizes_unicode_sender_domain_to_punycode() {
    assert_eq!(
        normalize_email(Some("Sender@ÉXAMPLE.COM".to_owned())).unwrap(),
        Some("Sender@xn--xample-9ua.com".to_owned())
    );
    assert_eq!(
        extract_email("辰星 <Sender@ÉXAMPLE.COM>"),
        Some("Sender@xn--xample-9ua.com".to_owned())
    );
}
