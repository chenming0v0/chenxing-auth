use chenxing_auth::{
    oauth::{
        code::AuthorizationCode,
        quota::{OAuthQuotaStore, QuotaConsumeResult, QuotaRefundCancel, refund_due_unix_millis},
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

fn metered_code(
    client_id: &str,
    reservation_id: &str,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> AuthorizationCode {
    let mut code = AuthorizationCode::new_at(
        client_id.to_owned(),
        "https://refund.example/callback".to_owned(),
        "7".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
        now,
    );
    code.expires_at = expires_at;
    code.quota_reservation_id = Some(reservation_id.to_owned());
    code
}

/// Worker snapshots a due reservation, then a successful redemption claims
/// the hashes. The later refund — both the direct compensation `refund()`
/// and a worker pass over a re-queued stale member — must not DECR.
#[tokio::test]
async fn successful_redemption_wins_over_stale_refund_snapshot() {
    let (store, codes, keyspace) = stores();
    let client_id = format!("quota-refund-race-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 10,
        monthly_auth_limit: Some(20),
    };
    let now = align_to_millis(OffsetDateTime::now_utc());
    let expires_at = now + Duration::seconds(60);
    let consumption = store
        .consume_with_limits_and_reservation_at(&client_id, limits, now)
        .await
        .expect("quota consumption");
    let reservation = consumption.reservation().expect("reservation");
    store
        .schedule_refund(&reservation, expires_at)
        .await
        .expect("schedule refund");

    let pending_key = keyspace.key("chenxing:oauth:quota:refund-pending");
    let mut connection = redis::Client::open(redis_url())
        .expect("Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let snapshotted: Vec<String> = connection
        .zrangebyscore_limit(&pending_key, 0, refund_due_unix_millis(expires_at), 0, 10)
        .await
        .expect("worker snapshot of due members");
    assert_eq!(snapshotted, vec![reservation.id().to_owned()]);

    let code = metered_code(&client_id, reservation.id(), now, expires_at);
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
        .expect("redeem after worker snapshot");
    assert!(consumed);

    store
        .refund(&reservation)
        .await
        .expect("stale snapshot refund must be a no-op after redemption");

    let _: () = connection
        .zadd(
            &pending_key,
            reservation.id(),
            refund_due_unix_millis(expires_at) as f64,
        )
        .await
        .expect("re-queue the snapshotted member as a stale worker would");
    let processed = store
        .run_refund_worker_pass(expires_at + Duration::seconds(1))
        .await
        .expect("worker pass over the stale member");
    assert_eq!(processed, 0);

    let snapshot = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot");
    assert_eq!(snapshot.daily_used, 1);
    assert_eq!(snapshot.monthly_used, 1);
}

/// Issue-path compensation refunds on `take() == Ok(None)`. After a successful
/// redemption that result means "already consumed", not "never stored".
#[tokio::test]
async fn compensation_take_none_does_not_refund_a_redeemed_reservation() {
    let (store, codes, keyspace) = stores();
    let client_id = format!("quota-refund-take-none-{}", Uuid::new_v4().simple());
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

    let code = metered_code(
        &client_id,
        reservation.id(),
        now,
        now + Duration::seconds(60),
    );
    codes.save(&code).await.expect("save code");
    assert!(
        codes
            .take_if_matches_with_quota_cancel(
                &code.value,
                &code,
                Some(QuotaRefundCancel::for_reservation_with_keyspace(
                    reservation.id(),
                    &keyspace,
                )),
            )
            .await
            .expect("redeem code")
    );
    assert!(
        codes
            .take(&code.value)
            .await
            .expect("compensation take")
            .is_none(),
        "successful redemption must leave take() returning Ok(None)"
    );

    store
        .refund(&reservation)
        .await
        .expect("compensation refund after take None");

    let snapshot = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot");
    assert_eq!(snapshot.daily_used, 1);
    assert_eq!(snapshot.monthly_used, 1);
}

/// Failed token exchange restores the code and the hash claim so a later
/// unused expiry can still refund.
#[tokio::test]
async fn restore_after_redemption_makes_unused_expiry_refundable_again() {
    let (store, codes, keyspace) = stores();
    let client_id = format!("quota-refund-restore-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 10,
        monthly_auth_limit: Some(20),
    };
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::seconds(60);
    let consumption = store
        .consume_with_limits_and_reservation_at(&client_id, limits, now)
        .await
        .expect("quota consumption");
    let reservation = consumption.reservation().expect("reservation");
    store
        .schedule_refund(&reservation, expires_at)
        .await
        .expect("schedule refund");

    let code = metered_code(&client_id, reservation.id(), now, expires_at);
    codes.save(&code).await.expect("save code");
    assert!(
        codes
            .take_if_matches_with_quota_cancel(
                &code.value,
                &code,
                Some(QuotaRefundCancel::for_reservation_with_keyspace(
                    reservation.id(),
                    &keyspace,
                )),
            )
            .await
            .expect("redeem code")
    );

    codes
        .restore_with_quota_refund(
            &code,
            60_000,
            Some(QuotaRefundCancel::for_reservation_with_keyspace(
                reservation.id(),
                &keyspace,
            )),
        )
        .await
        .expect("restore code and reservation hashes");

    let processed = store
        .run_refund_worker_pass(expires_at + Duration::seconds(1))
        .await
        .expect("refund restored reservation after expiry");
    assert_eq!(processed, 1);

    let snapshot = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot");
    assert_eq!(snapshot.daily_used, 0);
    assert_eq!(snapshot.monthly_used, 0);
}
