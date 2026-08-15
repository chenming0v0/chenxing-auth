use std::sync::Arc;

use ::redis::AsyncCommands;

use super::RedisAuthFailureLimiter;
use crate::auth_limiter::domain::{AUTH_FAILURE_WINDOW_SECONDS, AuthFailureLimits};
use crate::auth_limiter::{
    AuthFailureLimiter, AuthLimiterFailurePolicy, FailureDimension, metrics,
};
use crate::settings::{SecurityLimitsSetting, SettingsService};

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

fn limiter() -> RedisAuthFailureLimiter {
    RedisAuthFailureLimiter::new(::redis::Client::open(redis_url()).expect("Redis URL"))
}

fn unique_value(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

#[tokio::test]
async fn account_failures_are_rejected_after_ten_attempts() {
    let limiter = limiter();
    let account = unique_value("account");
    for attempt in 0..10 {
        assert_eq!(
            limiter
                .record_failure(FailureDimension::Account, &account)
                .await
                .expect("record account failure"),
            attempt == 9
        );
    }
    assert!(
        limiter
            .is_limited(FailureDimension::Account, &account)
            .await
            .expect("check account limit")
    );
}

#[tokio::test]
async fn successful_login_clears_account_failure_counter() {
    let limiter = limiter();
    let account = unique_value("account");
    limiter
        .record_failure(FailureDimension::Account, &account)
        .await
        .expect("record account failure");
    limiter
        .clear(FailureDimension::Account, &account)
        .await
        .expect("clear account failure");
    assert!(
        !limiter
            .is_limited(FailureDimension::Account, &account)
            .await
            .expect("check account limit")
    );
}

#[tokio::test]
async fn successful_login_clears_source_ip_failure_counter() {
    let limiter = limiter();
    let source_ip = unique_value("source-ip");
    limiter
        .record_failure(FailureDimension::SourceIp, &source_ip)
        .await
        .expect("record source IP failure");
    limiter
        .clear(FailureDimension::SourceIp, &source_ip)
        .await
        .expect("clear source IP failure");
    assert!(
        !limiter
            .is_limited(FailureDimension::SourceIp, &source_ip)
            .await
            .expect("check source IP limit")
    );
}

#[tokio::test]
async fn concurrent_account_failures_have_one_atomic_threshold_boundary() {
    let limiter = Arc::new(limiter());
    let account = unique_value("concurrent-account");
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let limiter = limiter.clone();
        let account = account.clone();
        tasks.push(tokio::spawn(async move {
            limiter
                .record_failure(FailureDimension::Account, &account)
                .await
                .expect("record concurrent failure")
        }));
    }
    let mut reached = 0;
    for task in tasks {
        reached += u8::from(task.await.expect("join concurrent failure"));
    }
    assert_eq!(reached, 1);
}

#[tokio::test]
async fn reservations_bound_concurrent_attempts_before_password_work() {
    let limiter = Arc::new(limiter());
    let account = unique_value("concurrent-reservation");
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let limiter = limiter.clone();
        let account = account.clone();
        tasks.push(tokio::spawn(async move {
            let dimensions = vec![(FailureDimension::Account, account)];
            if !limiter
                .reserve(dimensions.clone())
                .await
                .expect("reserve attempt")
            {
                return false;
            }
            limiter
                .record_reserved_failures(dimensions)
                .await
                .expect("commit reserved failure");
            true
        }));
    }
    let mut accepted = 0;
    for task in tasks {
        accepted += u8::from(task.await.expect("join reserved attempt"));
    }
    assert_eq!(accepted, FailureDimension::Account.limit() as u8);
}

#[tokio::test]
async fn batch_failure_uses_account_ticket_and_ip_dimensions_with_window_ttl() {
    let limiter = limiter();
    let account = unique_value("batch-account");
    let ticket = unique_value("batch-ticket");
    let source_ip = unique_value("batch-ip");
    for _ in 0..4 {
        let record = limiter
            .record_failures(vec![
                (FailureDimension::Account, account.clone()),
                (FailureDimension::Ticket, ticket.clone()),
                (FailureDimension::SourceIp, source_ip.clone()),
            ])
            .await
            .expect("record batch failure");
        assert!(record.reached.is_empty());
    }
    let record = limiter
        .record_failures(vec![
            (FailureDimension::Account, account.clone()),
            (FailureDimension::Ticket, ticket.clone()),
            (FailureDimension::SourceIp, source_ip.clone()),
        ])
        .await
        .expect("record threshold batch failure");
    assert!(record.reached(FailureDimension::Ticket));
    assert!(!record.reached(FailureDimension::Account));
    assert!(!record.reached(FailureDimension::SourceIp));

    let mut connection = limiter
        .client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    // 滑动窗口下 key 不带窗口后缀，可以直接寻址，不需要再 KEYS 扫描。
    let key = limiter.failure_key(FailureDimension::Ticket, &ticket);
    let key_type: String = connection
        .key_type(&key)
        .await
        .expect("failure counter key type");
    assert_eq!(
        key_type, "zset",
        "failures must be a sliding-window ZSET, not a fixed-window counter"
    );
    let ttl: i64 = connection.ttl(&key).await.expect("failure counter TTL");
    assert!(ttl > 0);
    // TTL 由窗口推导为 window + 1：条目按 score 老化，TTL 只负责回收空闲 key。
    assert!(ttl <= AUTH_FAILURE_WINDOW_SECONDS + 1);
}

/// 这是本次修复的回归锚点。
///
/// 旧实现把 `:floor(time / window)` 追加到 key 上做 epoch 对齐固定窗口，因此跨越
/// 一个窗口边界的失败会被记到两个不同的 key 上，计数凭空归零。CI 上
/// `password_success_does_not_reset_mfa_account_failures` 就是这样挂的：9 次失败落在
/// 03:00:00Z 之前的桶，随后两步落在之后的桶，账户没锁，返回 202 而不是 401。
/// 同一次 CI 的 coverage job 在 02:59:33Z 跑完同一个测试则通过——代码一字未改，
/// 只因墙钟位置不同而一过一挂。
///
/// 这里注入一个短窗口，并用 Redis 自己的 `TIME` 把两次失败刻意排布在
/// 「旧实现会跨桶、新实现仍在同一滑动窗口内」的位置上：
/// 第一次落在边界前 ~1.5s，第二次落在边界后 ~1.5s，间隔远小于 10s 窗口。
/// 固定窗口实现下第二次会看到一个空桶而返回 false；滑动窗口必须返回 true。
#[tokio::test]
async fn failures_survive_a_fixed_window_boundary_crossing() {
    /// 第一次失败落在边界前多少毫秒。这同时是「确实跨过边界」的抖动容差：
    /// 调度延迟超过它，两次失败会落进同一个旧桶，测试退化为不再区分两种实现。
    /// 那只是变弱，不会误报。
    const LEAD_MILLIS: i64 = 700;
    /// 两次失败的间隔。必须大于 `LEAD_MILLIS` 才能跨过边界；又必须远小于窗口，
    /// 否则第二次失败滑出窗口，新实现也会返回 false —— 那才是误报。
    ///
    /// 窗口下界取 10s（而不是刚好够用的 5s）就是为这条留余量：CI 上 821 个测试并发时
    /// 观测到约 3.3× 的整体放慢，1.4s 的 sleep 真实耗时可能接近 4.6s，5s 窗口只剩
    /// 几百毫秒余量，Redis 侧再排队一下就会误报。10s 窗口把余量抬到 8.6s。
    const GAP_MILLIS: i64 = 1_400;

    let client = ::redis::Client::open(redis_url()).expect("Redis URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    // 时钟必须取自 Redis：判定发生在 Redis 内部，测试进程的时钟可能有偏差。
    let (seconds, micros): (i64, i64) = ::redis::cmd("TIME")
        .query_async(&mut connection)
        .await
        .expect("Redis TIME");
    let millis = micros / 1_000;

    // 在候选窗口里挑「下一个边界最近」的那个，把对齐等待从「平均半个窗口」压到
    // 通常几百毫秒。下界 5s 保证 GAP 之外仍有充足余量。
    let (window_seconds, wait_millis) = (5..=12i64)
        .map(|window| {
            let window_millis = window * 1_000;
            let into_window = (seconds.rem_euclid(window) * 1_000) + millis;
            let wait = (window_millis - into_window - LEAD_MILLIS).rem_euclid(window_millis);
            (window, wait)
        })
        .min_by_key(|(_, wait)| *wait)
        .expect("candidate window");

    let limiter = RedisAuthFailureLimiter::with_limits(
        client,
        AuthLimiterFailurePolicy::FailClosed,
        AuthFailureLimits {
            window_seconds,
            account_limit: 2,
            ..AuthFailureLimits::default()
        },
    );
    let account = unique_value("boundary-account");

    tokio::time::sleep(std::time::Duration::from_millis(wait_millis as u64)).await;

    assert!(
        !limiter
            .record_failure(FailureDimension::Account, &account)
            .await
            .expect("record failure before the boundary"),
        "first of two failures must not reach a limit of 2"
    );

    // 跨过旧实现的 epoch 边界，但仍在同一个滑动窗口内。
    tokio::time::sleep(std::time::Duration::from_millis(GAP_MILLIS as u64)).await;

    assert!(
        limiter
            .record_failure(FailureDimension::Account, &account)
            .await
            .expect("record failure after the boundary"),
        "a sliding window must still count the failure recorded before the boundary; \
         the epoch-aligned fixed window reset it to zero here"
    );
    assert!(
        limiter
            .is_limited(FailureDimension::Account, &account)
            .await
            .expect("check account limit"),
        "the account must be locked after two failures inside one sliding window"
    );
}

/// 窗口本身仍然生效：条目滑出窗口后放行。
/// 与上一个测试构成一对——只证明「不归零」会掩盖「永不过期」这种反向缺陷。
#[tokio::test]
async fn failures_age_out_of_the_sliding_window() {
    const WINDOW_SECONDS: i64 = 1;
    let limiter = RedisAuthFailureLimiter::with_limits(
        ::redis::Client::open(redis_url()).expect("Redis URL"),
        AuthLimiterFailurePolicy::FailClosed,
        AuthFailureLimits {
            window_seconds: WINDOW_SECONDS,
            account_limit: 1,
            ..AuthFailureLimits::default()
        },
    );
    let account = unique_value("aging-account");
    assert!(
        limiter
            .record_failure(FailureDimension::Account, &account)
            .await
            .expect("record failure"),
        "one failure reaches a limit of 1"
    );
    assert!(
        limiter
            .is_limited(FailureDimension::Account, &account)
            .await
            .expect("check inside the window")
    );
    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;
    assert!(
        !limiter
            .is_limited(FailureDimension::Account, &account)
            .await
            .expect("check after the window"),
        "the failure left the sliding window and must no longer block"
    );
}

/// 成功认证归还预留，不消耗失败配额。
/// 预留是「在途」而非「历史」，因此 release 之后窗口内的失败数必须仍是 0。
#[tokio::test]
async fn released_reservations_do_not_consume_failure_budget() {
    let limiter = limiter();
    let account = unique_value("released-account");
    let dimensions = vec![(FailureDimension::Account, account.clone())];
    for _ in 0..FailureDimension::Account.limit() + 5 {
        assert!(
            limiter
                .reserve(dimensions.clone())
                .await
                .expect("reserve attempt")
        );
        limiter
            .release(dimensions.clone())
            .await
            .expect("release attempt");
    }
    assert!(
        !limiter
            .is_limited(FailureDimension::Account, &account)
            .await
            .expect("check account limit"),
        "successful authentications must not accumulate failure budget"
    );
}

#[tokio::test]
async fn redis_failure_policy_is_explicit_and_observable() {
    let client = ::redis::Client::open("redis://127.0.0.1:1/").expect("Redis URL");
    let fail_open = RedisAuthFailureLimiter::with_failure_policy(
        client.clone(),
        AuthLimiterFailurePolicy::FailOpen,
    );
    let fail_closed =
        RedisAuthFailureLimiter::with_failure_policy(client, AuthLimiterFailurePolicy::FailClosed);
    let before = metrics().redis_errors;
    assert!(
        !fail_open
            .is_limited(FailureDimension::Account, "failure-policy-open")
            .await
            .expect("fail-open check")
    );
    assert!(
        !fail_open
            .record_failure(FailureDimension::Account, "failure-policy-open")
            .await
            .expect("fail-open record")
    );
    assert!(
        fail_open
            .reserve(vec![(
                FailureDimension::Account,
                "failure-policy-open-reserve".to_owned(),
            )])
            .await
            .expect("fail-open reserve")
    );
    assert!(
        fail_closed
            .is_limited(FailureDimension::Account, "failure-policy-closed")
            .await
            .is_err()
    );
    assert!(
        fail_closed
            .record_failure(FailureDimension::Account, "failure-policy-closed")
            .await
            .is_err()
    );
    assert!(
        fail_closed
            .reserve(vec![(
                FailureDimension::Account,
                "failure-policy-closed-reserve".to_owned(),
            )])
            .await
            .is_err()
    );
    assert!(metrics().redis_errors >= before + 6);
}

/// 阈值来源不可用时的限流器行为（#300）。
///
/// Redis 正常、settings 数据库不可达：fail-open 必须继续用最后已知安全值限流，
/// 认证不因为一次配置读取失败而 500。这里用一个 `account_limit = 2` 的启动期默认，
/// 两次失败之后必须真的锁住——证明降级路径不是「不限流」，而是「按已知阈值限流」。
#[tokio::test]
async fn fail_open_still_enforces_limits_when_settings_are_unavailable() {
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting {
        account_failure_limit: 2,
        ..SecurityLimitsSetting::default()
    });
    let limiter = RedisAuthFailureLimiter::with_settings(
        ::redis::Client::open(redis_url()).expect("Redis URL"),
        AuthLimiterFailurePolicy::FailOpen,
        settings,
    );
    let account = unique_value("settings-degraded-account");
    let before = metrics().settings_errors;

    assert!(
        !limiter
            .record_failure(FailureDimension::Account, &account)
            .await
            .expect("fail-open must not surface the settings failure"),
        "the first of two failures must not reach the limit"
    );
    assert!(
        limiter
            .record_failure(FailureDimension::Account, &account)
            .await
            .expect("fail-open must not surface the settings failure"),
        "the degraded limits must still be enforced, not skipped"
    );
    assert!(
        limiter
            .is_limited(FailureDimension::Account, &account)
            .await
            .expect("fail-open check"),
        "the account must be locked by the last known safe limits"
    );
    assert!(
        metrics().settings_errors > before,
        "every degraded limits read must be observable"
    );
}

/// fail-closed 下 settings 不可用必须明确拒绝，即使 Redis 正常。
/// 这是与上一个测试成对的另一半：只验证 fail-open 会掩盖策略根本没生效的情况。
#[tokio::test]
async fn fail_closed_rejects_when_settings_are_unavailable() {
    let settings = SettingsService::unreachable_for_tests(SecurityLimitsSetting::default());
    let limiter = RedisAuthFailureLimiter::with_settings(
        ::redis::Client::open(redis_url()).expect("Redis URL"),
        AuthLimiterFailurePolicy::FailClosed,
        settings,
    );
    let account = unique_value("settings-closed-account");
    let dimensions = vec![(FailureDimension::Account, account.clone())];
    let before = metrics().settings_errors;

    assert!(
        limiter
            .is_limited(FailureDimension::Account, &account)
            .await
            .is_err()
    );
    assert!(limiter.reserve(dimensions.clone()).await.is_err());
    assert!(limiter.record_failures(dimensions.clone()).await.is_err());
    assert!(
        limiter
            .record_reserved_failures(dimensions.clone())
            .await
            .is_err()
    );
    assert!(metrics().settings_errors >= before + 4);

    // `clear` 与 `release` 不读取阈值：成功认证之后不能因为配置读取失败而把用户
    // 继续锁在限流里，也不能把在途配额挂到 TTL 过期。
    limiter
        .clear(FailureDimension::Account, &account)
        .await
        .expect("clear must not depend on the settings store");
    limiter
        .release(dimensions)
        .await
        .expect("release must not depend on the settings store");
}
