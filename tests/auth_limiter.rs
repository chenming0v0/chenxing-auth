use std::sync::Arc;

use chenxing_auth::auth_limiter::{AuthFailureLimiter, FailureDimension, RedisAuthFailureLimiter};

fn limiter() -> RedisAuthFailureLimiter {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    RedisAuthFailureLimiter::new(redis::Client::open(url).expect("Redis URL"))
}

#[tokio::test]
async fn redis_reservation_script_caps_concurrent_failures_at_the_account_limit() {
    let limiter = Arc::new(limiter());
    let account = format!("integration-{}", uuid::Uuid::new_v4().simple());
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let limiter = limiter.clone();
        let account = account.clone();
        tasks.push(tokio::spawn(async move {
            let dimensions = vec![(FailureDimension::Account, account)];
            let reserved = limiter.reserve(dimensions.clone()).await.expect("reserve");
            if reserved {
                limiter
                    .record_reserved_failures(dimensions)
                    .await
                    .expect("record reserved failure");
            }
            reserved
        }));
    }
    let mut accepted = 0;
    for task in tasks {
        accepted += u8::from(task.await.expect("join"));
    }
    assert_eq!(accepted, FailureDimension::Account.limit() as u8);
}
