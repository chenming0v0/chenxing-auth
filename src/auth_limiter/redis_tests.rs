use std::sync::Arc;

use ::redis::AsyncCommands;

use super::RedisAuthFailureLimiter;
use crate::auth_limiter::{AuthFailureLimiter, AuthLimiterFailurePolicy, FailureDimension};

fn limiter() -> RedisAuthFailureLimiter {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    RedisAuthFailureLimiter::new(::redis::Client::open(url).expect("Redis URL"))
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
            if !limiter.reserve(dimensions.clone()).await.expect("reserve attempt") {
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

    let (window, _) = RedisAuthFailureLimiter::window();
    let key = RedisAuthFailureLimiter::key(FailureDimension::Ticket, &ticket, window);
    let mut connection = limiter
        .client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let ttl: i64 = connection.ttl(key).await.expect("failure counter TTL");
    assert!(ttl > 0);
    assert!(ttl <= super::AUTH_FAILURE_WINDOW_SECONDS);
}

#[tokio::test]
async fn redis_failure_policy_is_explicit_and_observable() {
    let client = ::redis::Client::open("redis://127.0.0.1:1/").expect("Redis URL");
    let fail_open = RedisAuthFailureLimiter::with_failure_policy(
        client.clone(),
        AuthLimiterFailurePolicy::FailOpen,
    );
    let fail_closed = RedisAuthFailureLimiter::with_failure_policy(
        client,
        AuthLimiterFailurePolicy::FailClosed,
    );
    let before = super::metrics().redis_errors;
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
    assert!(fail_open
        .reserve(vec![(
            FailureDimension::Account,
            "failure-policy-open-reserve".to_owned(),
        )])
        .await
        .expect("fail-open reserve"));
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
    assert!(fail_closed
        .reserve(vec![(
            FailureDimension::Account,
            "failure-policy-closed-reserve".to_owned(),
        )])
        .await
        .is_err());
    assert!(super::metrics().redis_errors >= before + 6);
}
