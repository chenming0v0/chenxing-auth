use chenxing_auth::oauth::rate_limit::QpsRateLimiter;
use redis::AsyncCommands;

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

fn limiter() -> QpsRateLimiter {
    QpsRateLimiter::new(redis::Client::open(redis_url()).expect("Redis URL"))
}

fn limiter_with_window(window_ms: i64) -> QpsRateLimiter {
    QpsRateLimiter::with_window_ms(
        redis::Client::open(redis_url()).expect("Redis URL"),
        window_ms,
    )
}

#[tokio::test]
async fn sliding_window_rejects_requests_over_the_limit() {
    let limiter = limiter();
    let client_id = format!("qps-test-{}", uuid::Uuid::new_v4().simple());
    assert!(limiter.allow(&client_id, 2).await.expect("first request"));
    assert!(limiter.allow(&client_id, 2).await.expect("second request"));
    assert!(!limiter.allow(&client_id, 2).await.expect("third request"));
}

#[tokio::test]
async fn concurrent_requests_share_the_same_window() {
    let limiter = limiter();
    let client_id = format!("qps-concurrent-{}", uuid::Uuid::new_v4().simple());
    let (first, second, third) = tokio::join!(
        limiter.allow(&client_id, 2),
        limiter.allow(&client_id, 2),
        limiter.allow(&client_id, 2),
    );
    let mut allowed = [
        first.expect("first concurrent request"),
        second.expect("second concurrent request"),
        third.expect("third concurrent request"),
    ];
    allowed.sort_unstable();
    assert_eq!(allowed, [false, true, true]);
}

#[tokio::test]
async fn scoped_window_is_independent_of_the_instance_window() {
    let limiter = limiter();
    let scope = format!("chenxing:test:scoped:{}", uuid::Uuid::new_v4().simple());
    assert!(
        limiter
            .allow_scoped(&scope, 1, 60_000)
            .await
            .expect("first scoped request")
    );
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    assert!(
        !limiter
            .allow_scoped(&scope, 1, 60_000)
            .await
            .expect("second scoped request"),
        "60s scoped window must still count the entry recorded 1.2s ago"
    );
}

#[tokio::test]
async fn default_window_expires_after_one_second() {
    let limiter = limiter();
    let client_id = format!("qps-default-window-{}", uuid::Uuid::new_v4().simple());
    assert!(limiter.allow(&client_id, 1).await.expect("first request"));
    assert!(
        !limiter.allow(&client_id, 1).await.expect("second request"),
        "second request inside the 1s window must be rejected"
    );
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    assert!(
        limiter.allow(&client_id, 1).await.expect("third request"),
        "1.2s later the entry left the 1s window and the request is allowed again"
    );
}

#[tokio::test]
async fn large_window_keeps_rejecting_after_one_second() {
    let limiter = limiter_with_window(60_000);
    let client_id = format!("qps-large-window-{}", uuid::Uuid::new_v4().simple());
    assert!(limiter.allow(&client_id, 1).await.expect("first request"));
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    assert!(
        !limiter.allow(&client_id, 1).await.expect("second request"),
        "60s window must still count the entry recorded 1.2s ago"
    );

    let mut connection = redis::Client::open(redis_url())
        .expect("Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let ttl: i64 = connection
        .ttl(format!("chenxing:qps:{client_id}"))
        .await
        .expect("key TTL");
    assert!(
        ttl > 2,
        "key TTL must scale with the window, got {ttl}s (hardcoded 2s would evict entries)"
    );
}
