use chenxing_auth::{
    oauth::{
        code::AuthorizationCode,
        quota::{OAuthQuotaStore, QuotaConsumeResult, QuotaRefundCancel},
        store::AuthorizationCodeStore,
    },
    plans::domain::AuthQuotaLimits,
    redis_keyspace::RedisKeyspace,
};
use redis::AsyncCommands;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

fn stores() -> (OAuthQuotaStore, AuthorizationCodeStore, RedisKeyspace) {
    let client = redis::Client::open(redis_url()).expect("Redis URL");
    let keyspace = RedisKeyspace::new(&format!("quota-refund-{}", Uuid::new_v4().simple()))
        .expect("test Redis namespace");
    (
        OAuthQuotaStore::with_keyspace(client.clone(), keyspace.clone()),
        AuthorizationCodeStore::with_keyspace(client, keyspace.clone()),
        keyspace,
    )
}

#[tokio::test]
async fn expired_unredeemed_code_refunds_quota() {
    let (store, _codes, _keyspace) = stores();
    let client_id = format!("quota-refund-expired-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 10,
        monthly_auth_limit: Some(20),
    };
    let now = OffsetDateTime::now_utc();
    let consumption = store
        .consume_with_limits_and_reservation_at(&client_id, limits, now)
        .await
        .expect("quota consumption");
    assert_eq!(consumption.result, QuotaConsumeResult::Allowed);
    let reservation = consumption.reservation().expect("reservation");

    store
        .schedule_refund(&reservation, now.unix_timestamp() + 60)
        .await
        .expect("schedule refund");

    let processed = store
        .run_refund_worker_pass(now + Duration::seconds(120))
        .await
        .expect("refund worker pass");
    assert_eq!(processed, 1);

    let snapshot = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot");
    assert_eq!(snapshot.daily_used, 0);
    assert_eq!(snapshot.monthly_used, 0);
}

#[tokio::test]
async fn redeemed_code_keeps_quota_and_cancels_pending_refund() {
    let (store, codes, keyspace) = stores();
    let client_id = format!("quota-refund-redeemed-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 10,
        monthly_auth_limit: Some(20),
    };
    let now = OffsetDateTime::now_utc();
    let consumption = store
        .consume_with_limits_and_reservation_at(&client_id, limits, now)
        .await
        .expect("quota consumption");
    let reservation = consumption.reservation().expect("reservation");
    store
        .schedule_refund(&reservation, now.unix_timestamp() + 60)
        .await
        .expect("schedule refund");

    let mut code = AuthorizationCode::new(
        client_id.clone(),
        "https://refund.example/callback".to_owned(),
        "7".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
    );
    code.quota_reservation_id = Some(reservation.id().to_owned());
    codes.save(&code).await.expect("save code");
    let consumed = codes
        .take_if_matches_with_quota_cancel(
            &code.value,
            &code,
            Some(QuotaRefundCancel::for_reservation_with_keyspace(
                reservation.id(),
                &keyspace,
            )),
        )
        .await
        .expect("consume code");
    assert!(consumed);

    let processed = store
        .run_refund_worker_pass(now + Duration::seconds(120))
        .await
        .expect("refund worker pass");
    assert_eq!(processed, 0);

    let snapshot = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot");
    assert_eq!(snapshot.daily_used, 1);
    assert_eq!(snapshot.monthly_used, 1);

    let mut connection = redis::Client::open(redis_url())
        .expect("Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let remaining: i64 = connection
        .zcard(keyspace.key("chenxing:oauth:quota:refund-pending"))
        .await
        .expect("pending refund count");
    assert_eq!(remaining, 0);
}
