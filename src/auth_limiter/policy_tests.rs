use std::time::Duration;

use super::LimiterPolicy;
use crate::auth_limiter::domain::{
    ACCOUNT_FAILURE_LIMIT, AuthFailureLimits, AuthLimiterError, AuthLimiterFailurePolicy,
    FailureDimension, IP_FAILURE_LIMIT,
};
use crate::settings::{SecurityLimitsCache, SecurityLimitsSetting, SettingsService};

fn dimensions() -> Vec<(FailureDimension, String)> {
    vec![(FailureDimension::Account, "user@example.com".to_owned())]
}

fn tightened() -> SecurityLimitsSetting {
    SecurityLimitsSetting {
        account_failure_limit: 3,
        ip_failure_limit: 7,
        ..SecurityLimitsSetting::default()
    }
}

/// 没有 `SettingsService` 时（测试与自定义部署）阈值来自构造参数，不产生任何读取。
#[tokio::test]
async fn a_fixed_policy_never_reads_settings() {
    let policy = LimiterPolicy::fixed(
        AuthLimiterFailurePolicy::FailClosed,
        AuthFailureLimits {
            account_limit: 4,
            ..AuthFailureLimits::default()
        },
    );
    let limits = policy
        .current_limits("check", &dimensions())
        .await
        .expect("fixed limits are always available");
    assert_eq!(limits.limit_for(FailureDimension::Account), 4);
}

/// 稳态：命中缓存的阈值读取成功，且不被当作降级。
#[tokio::test]
async fn cached_limits_are_used_without_invoking_the_failure_policy() {
    let cache = SecurityLimitsCache::with_durations(
        SecurityLimitsSetting::default(),
        Duration::from_secs(60),
        Duration::from_secs(60),
    );
    cache.store(tightened());
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default())
        .with_security_limits_cache(cache);
    let policy = LimiterPolicy::from_settings(AuthLimiterFailurePolicy::FailClosed, settings);

    let limits = policy
        .current_limits("check", &dimensions())
        .await
        .expect("a fresh cache entry must not trip the failure policy");
    assert_eq!(limits.limit_for(FailureDimension::Account), 3);
    assert_eq!(limits.limit_for(FailureDimension::SourceIp), 7);
}

/// #300：fail-open 下 settings 故障不再让认证失败，而是带着最后已知安全值继续限流。
#[tokio::test]
async fn fail_open_settings_failure_keeps_authentication_working_with_known_limits() {
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default());
    let policy = LimiterPolicy::from_settings(AuthLimiterFailurePolicy::FailOpen, settings);
    let before = super::metrics().settings_errors;

    let limits = policy
        .current_limits("reserve", &dimensions())
        .await
        .expect("fail-open must not surface a settings failure to the caller");

    // 降级取值仍然是有效阈值：限流继续生效，只是可能陈旧。
    assert_eq!(
        limits.limit_for(FailureDimension::Account),
        ACCOUNT_FAILURE_LIMIT
    );
    assert_eq!(
        limits.limit_for(FailureDimension::SourceIp),
        IP_FAILURE_LIMIT
    );
    assert!(super::metrics().settings_errors > before);
}

/// #300：fail-closed 下 settings 故障必须明确拒绝，与 Redis 不可用时处置一致。
#[tokio::test]
async fn fail_closed_settings_failure_is_rejected_and_counted() {
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default());
    let policy = LimiterPolicy::from_settings(AuthLimiterFailurePolicy::FailClosed, settings);
    let before = super::metrics().settings_errors;

    assert!(matches!(
        policy.current_limits("reserve", &dimensions()).await,
        Err(AuthLimiterError::Storage)
    ));
    assert!(super::metrics().settings_errors > before);
}

/// 降级用的是最后已知值，不是启动期默认：管理员收紧过的阈值不能因为一次读取失败被放宽。
#[tokio::test]
async fn fail_open_settings_failure_prefers_the_last_known_limits() {
    let cache = SecurityLimitsCache::with_durations(
        SecurityLimitsSetting::default(),
        Duration::ZERO,
        Duration::ZERO,
    );
    cache.store(tightened());
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default())
        .with_security_limits_cache(cache);
    let policy = LimiterPolicy::from_settings(AuthLimiterFailurePolicy::FailOpen, settings);

    let limits = policy
        .current_limits("check", &dimensions())
        .await
        .expect("fail-open degrades instead of failing");
    assert_eq!(limits.limit_for(FailureDimension::Account), 3);
    assert_eq!(limits.limit_for(FailureDimension::SourceIp), 7);
}

/// Redis 故障语义未被本次改动削弱：四条处置分支保持原有返回值。
#[test]
fn redis_failure_dispatch_is_unchanged_by_the_settings_path() {
    let fail_open = LimiterPolicy::fixed(
        AuthLimiterFailurePolicy::FailOpen,
        AuthFailureLimits::default(),
    );
    let fail_closed = LimiterPolicy::fixed(
        AuthLimiterFailurePolicy::FailClosed,
        AuthFailureLimits::default(),
    );
    let dimensions = dimensions();

    assert!(
        !fail_open
            .unavailable_bool("check", &dimensions)
            .expect("fail-open returns a value"),
        "fail-open must not report a limit it could not verify"
    );
    assert!(
        !fail_open
            .unavailable_reservation("reserve", &dimensions)
            .expect("fail-open grants the reservation")
            .is_denied(),
    );
    assert!(
        !fail_open
            .unavailable_record("record", &dimensions)
            .expect("fail-open reports the failure as not recorded")
            .was_recorded()
    );
    assert!(fail_open.unavailable_unit("release", &dimensions).is_ok());

    assert!(matches!(
        fail_closed.unavailable_bool("check", &dimensions),
        Err(AuthLimiterError::Storage)
    ));
    assert!(matches!(
        fail_closed.unavailable_reservation("reserve", &dimensions),
        Err(AuthLimiterError::Storage)
    ));
    assert!(matches!(
        fail_closed.unavailable_record("record", &dimensions),
        Err(AuthLimiterError::Storage)
    ));
    assert!(matches!(
        fail_closed.unavailable_unit("release", &dimensions),
        Err(AuthLimiterError::Storage)
    ));
}

/// `SecurityLimitsSetting` 到 `AuthFailureLimits` 的字段映射不能错位。
#[test]
fn security_limits_map_onto_the_limiter_dimensions() {
    let limits = AuthFailureLimits::from(&SecurityLimitsSetting {
        auth_failure_window_seconds: 111,
        account_failure_limit: 2,
        ip_failure_limit: 3,
        totp_ticket_failure_limit: 4,
        ..SecurityLimitsSetting::default()
    });
    assert_eq!(limits.window(), 111);
    assert_eq!(limits.limit_for(FailureDimension::Account), 2);
    assert_eq!(limits.limit_for(FailureDimension::SourceIp), 3);
    assert_eq!(limits.limit_for(FailureDimension::Ticket), 4);
}
