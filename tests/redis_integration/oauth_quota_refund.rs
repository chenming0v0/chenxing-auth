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

fn align_to_millis(now: OffsetDateTime) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(
        now.unix_timestamp_nanos().div_euclid(1_000_000) * 1_000_000,
    )
    .expect("millisecond-aligned timestamp")
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
        .schedule_refund(&reservation, now + Duration::seconds(60))
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
        .schedule_refund(&reservation, now + Duration::seconds(60))
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

#[tokio::test]
async fn refund_waits_for_exact_subsecond_expiry() {
    let (store, _codes, _keyspace) = stores();
    let client_id = format!("quota-refund-boundary-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 10,
        monthly_auth_limit: Some(20),
    };
    let now = align_to_millis(OffsetDateTime::now_utc());
    let expires_at = now + Duration::seconds(60) + Duration::milliseconds(900);
    let consumption = store
        .consume_with_limits_and_reservation_at(&client_id, limits, now)
        .await
        .expect("quota consumption");
    let reservation = consumption.reservation().expect("reservation");
    store
        .schedule_refund(&reservation, expires_at)
        .await
        .expect("schedule refund");

    let before = store
        .run_refund_worker_pass(expires_at - Duration::milliseconds(1))
        .await
        .expect("refund worker pass before exact expiry");
    assert_eq!(before, 0);
    let held = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot before expiry");
    assert_eq!(held.daily_used, 1);
    assert_eq!(held.monthly_used, 1);

    let after = store
        .run_refund_worker_pass(expires_at)
        .await
        .expect("refund worker pass at exact expiry");
    assert_eq!(after, 1);
    let refunded = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot after expiry");
    assert_eq!(refunded.daily_used, 0);
    assert_eq!(refunded.monthly_used, 0);
}

#[tokio::test]
async fn redeemed_code_inside_subsecond_window_keeps_quota() {
    let (store, codes, keyspace) = stores();
    let client_id = format!("quota-refund-window-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 10,
        monthly_auth_limit: Some(20),
    };
    let now = align_to_millis(OffsetDateTime::now_utc());
    let expires_at = now + Duration::seconds(60) + Duration::milliseconds(900);
    let consumption = store
        .consume_with_limits_and_reservation_at(&client_id, limits, now)
        .await
        .expect("quota consumption");
    let reservation = consumption.reservation().expect("reservation");
    store
        .schedule_refund(&reservation, expires_at)
        .await
        .expect("schedule refund");

    let mut code = AuthorizationCode::new_at(
        client_id.clone(),
        "https://refund.example/callback".to_owned(),
        "7".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
        now,
    );
    code.expires_at = expires_at;
    code.quota_reservation_id = Some(reservation.id().to_owned());

    let mut still_valid = code.clone();
    still_valid
        .redeem_at(expires_at - Duration::milliseconds(1))
        .expect("code remains redeemable before exact expiry");
    let mut expired = code.clone();
    assert_eq!(
        expired.redeem_at(expires_at),
        Err(chenxing_auth::oauth::code::CodeError::Expired)
    );

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
        .expect("consume code inside the subsecond window");
    assert!(consumed);

    let processed = store
        .run_refund_worker_pass(expires_at + Duration::seconds(1))
        .await
        .expect("refund worker pass after expiry");
    assert_eq!(processed, 0);

    let snapshot = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot");
    assert_eq!(snapshot.daily_used, 1);
    assert_eq!(snapshot.monthly_used, 1);
}

#[tokio::test]
async fn legacy_second_score_does_not_refund_until_next_second() {
    let (store, _codes, keyspace) = stores();
    let client_id = format!("quota-refund-legacy-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 10,
        monthly_auth_limit: Some(20),
    };
    let now = align_to_millis(OffsetDateTime::now_utc());
    let expires_at = now + Duration::seconds(60) + Duration::milliseconds(900);
    let consumption = store
        .consume_with_limits_and_reservation_at(&client_id, limits, now)
        .await
        .expect("quota consumption");
    let reservation = consumption.reservation().expect("reservation");
    store
        .schedule_refund(&reservation, expires_at)
        .await
        .expect("schedule refund");

    let mut connection = redis::Client::open(redis_url())
        .expect("Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: () = connection
        .zadd(
            keyspace.key("chenxing:oauth:quota:refund-pending"),
            reservation.id(),
            expires_at.unix_timestamp() as f64,
        )
        .await
        .expect("overwrite score with legacy unix seconds");

    let before_next_second = store
        .run_refund_worker_pass(expires_at)
        .await
        .expect("legacy score must wait until the next second");
    assert_eq!(before_next_second, 0);
    let held = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot before next second");
    assert_eq!(held.daily_used, 1);

    let next_second = OffsetDateTime::from_unix_timestamp(expires_at.unix_timestamp() + 1)
        .expect("next unix second");
    let after_next_second = store
        .run_refund_worker_pass(next_second)
        .await
        .expect("legacy score becomes due after the whole second");
    assert_eq!(after_next_second, 1);
    let refunded = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot after next second");
    assert_eq!(refunded.daily_used, 0);
    assert_eq!(refunded.monthly_used, 0);
}

#[tokio::test]
async fn full_modern_batch_still_refunds_a_due_legacy_reservation() {
    let (store, _codes, keyspace) = stores();
    let client_id = format!("quota-refund-fair-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 200,
        monthly_auth_limit: Some(200),
    };
    let now = align_to_millis(OffsetDateTime::now_utc());
    let expires_at = now + Duration::seconds(60);

    let legacy_consumption = store
        .consume_with_limits_and_reservation_at(&client_id, limits, now)
        .await
        .expect("legacy quota consumption");
    let legacy = legacy_consumption
        .reservation()
        .expect("legacy reservation");
    store
        .schedule_refund(&legacy, expires_at)
        .await
        .expect("schedule legacy refund");

    let pending_key = keyspace.key("chenxing:oauth:quota:refund-pending");
    let mut connection = redis::Client::open(redis_url())
        .expect("Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: () = connection
        .zadd(
            &pending_key,
            legacy.id(),
            expires_at.unix_timestamp() as f64,
        )
        .await
        .expect("rewrite legacy score in unix seconds");

    for _ in 0..100 {
        let consumption = store
            .consume_with_limits_and_reservation_at(&client_id, limits, now)
            .await
            .expect("modern quota consumption");
        let reservation = consumption.reservation().expect("modern reservation");
        store
            .schedule_refund(&reservation, expires_at)
            .await
            .expect("schedule modern refund");
    }

    let pass_time = OffsetDateTime::from_unix_timestamp(expires_at.unix_timestamp() + 1)
        .expect("whole next second");
    let processed = store
        .run_refund_worker_pass(pass_time)
        .await
        .expect("mixed-format refund pass");
    assert_eq!(processed, 100, "worker batch size remains bounded");
    assert_eq!(
        connection
            .zscore::<_, _, Option<f64>>(&pending_key, legacy.id())
            .await
            .expect("legacy pending score"),
        None,
        "a continuously full modern queue must not starve the legacy reservation"
    );

    let snapshot = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("quota snapshot after fair pass");
    assert_eq!(snapshot.daily_used, 1);
    assert_eq!(snapshot.monthly_used, 1);
}
