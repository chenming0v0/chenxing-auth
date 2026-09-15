//! Shared refund-queue isolation regression (issue #710).
//!
//! Mechanism under test: the "pending refunds" ZSET is namespaced by
//! `RedisKeyspace` **only** — it is not partitioned by `client_id`. A worker
//! pass run through any `OAuthQuotaStore` that shares a keyspace scans the whole
//! keyspace queue, reads each reservation payload (which embeds the *owning*
//! client's period keys), and refunds them. So two clients that share a
//! keyspace cross-refund each other even though their client IDs are UUIDs.
//!
//! This is a deterministic, Redis-only test: no PostgreSQL, no template
//! fixture, no sleeps, no concurrency. It documents the mechanism and the
//! `RedisKeyspace` boundary that contains it; it does not reproduce any exact
//! historical CI interleaving and never touches the real legacy queue.

use chenxing_auth::{
    oauth::quota::{OAuthQuotaStore, QuotaConsumeResult, QuotaReservation},
    plans::domain::AuthQuotaLimits,
    redis_keyspace::RedisKeyspace,
};
use time::{Duration, OffsetDateTime, Time};
use uuid::Uuid;

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

fn store(keyspace: &RedisKeyspace) -> OAuthQuotaStore {
    let client = redis::Client::open(redis_url()).expect("Redis URL");
    OAuthQuotaStore::with_keyspace(client, keyspace.clone())
}

fn limits() -> AuthQuotaLimits {
    AuthQuotaLimits {
        daily_auth_limit: 2,
        monthly_auth_limit: Some(2),
    }
}

/// Deterministic clock two days ahead, pinned to noon UTC.
///
/// `+2 days` keeps every absolute EXPIREAT the consume script derives (day and
/// month boundaries) in the real server's future no matter when the test runs.
/// Pinning to noon keeps `expires_at`/`future_scan` a few minutes later on the
/// *same* calendar day, so no period counter or reservation record crosses a
/// midnight/month boundary mid-scenario. No past hardcoded dates.
fn base_time() -> OffsetDateTime {
    let two_days = OffsetDateTime::now_utc() + Duration::days(2);
    two_days.replace_time(Time::from_hms(12, 0, 0).expect("noon is a valid time"))
}

/// Consume one authorization and return its reservation; the caller's inputs
/// must allow it.
async fn reserve(
    store: &OAuthQuotaStore,
    client_id: &str,
    now: OffsetDateTime,
) -> QuotaReservation {
    let consumption = store
        .consume_with_limits_and_reservation_at(client_id, limits(), now)
        .await
        .expect("quota consumption");
    assert_eq!(
        consumption.result,
        QuotaConsumeResult::Allowed,
        "reservation requires an allowed consumption"
    );
    consumption
        .reservation()
        .expect("allowed consumption reserves")
}

async fn schedule(
    store: &OAuthQuotaStore,
    reservation: &QuotaReservation,
    expires_at: OffsetDateTime,
) {
    store
        .schedule_refund(reservation, expires_at)
        .await
        .expect("schedule refund");
}

async fn used(store: &OAuthQuotaStore, client_id: &str, now: OffsetDateTime) -> (u64, u64) {
    let snapshot = store
        .snapshot_at(client_id, Some(limits()), now)
        .await
        .expect("snapshot");
    (snapshot.daily_used, snapshot.monthly_used)
}

#[tokio::test]
async fn refund_queue_is_shared_across_client_ids_within_a_keyspace() {
    // IDs are shared by both scenarios so only the keyspace differs.
    let id_a = format!("refund-scope-a-{}", Uuid::new_v4().simple());
    let id_b = format!("refund-scope-b-{}", Uuid::new_v4().simple());
    let token = Uuid::new_v4().simple();
    let base = base_time();
    let expires_at = base + Duration::seconds(300);
    let future_scan = base + Duration::seconds(360);

    // ---- Control: two clients share one keyspace, so one client's worker ----
    // ---- drains the other client's reservations. ---------------------------
    let shared =
        RedisKeyspace::new(&format!("refund-scope-{token}-control")).expect("shared test keyspace");
    let store_a = store(&shared);
    let store_b = store(&shared);

    let a1 = reserve(&store_a, &id_a, base).await;
    let a2 = reserve(&store_a, &id_a, base).await;
    schedule(&store_a, &a1, expires_at).await;
    schedule(&store_a, &a2, expires_at).await;
    assert_eq!(used(&store_a, &id_a, base).await, (2, 2));

    let b1 = reserve(&store_b, &id_b, base).await;
    schedule(&store_b, &b1, expires_at).await;

    // B's worker scans the keyspace-wide queue and consumes all three entries,
    // including A's two. This is the defect, demonstrated, not a failure here:
    // the queue does not partition by client ID.
    let crossed = store_b
        .run_refund_worker_pass(future_scan)
        .await
        .expect("shared-keyspace refund pass");
    assert_eq!(
        crossed, 3,
        "a worker pass over the shared queue refunds every client's reservations"
    );
    assert_eq!(
        used(&store_a, &id_a, future_scan).await,
        (0, 0),
        "A's quota was refunded by B's worker"
    );
    assert_eq!(
        store_a
            .consume_with_limits_at(&id_a, limits(), future_scan)
            .await
            .expect("post-refund consumption"),
        QuotaConsumeResult::Allowed,
        "A's counters are free again after the crossed refund"
    );

    // ---- Protected: distinct keyspaces keep B's worker off A's records. ----
    let keyspace_a = RedisKeyspace::new(&format!("refund-scope-{token}-a"))
        .expect("independent test keyspace A");
    let keyspace_b = RedisKeyspace::new(&format!("refund-scope-{token}-b"))
        .expect("independent test keyspace B");
    let store_pa = store(&keyspace_a);
    let store_pb = store(&keyspace_b);

    let pa1 = reserve(&store_pa, &id_a, base).await;
    let pa2 = reserve(&store_pa, &id_a, base).await;
    schedule(&store_pa, &pa1, expires_at).await;
    schedule(&store_pa, &pa2, expires_at).await;

    let pb1 = reserve(&store_pb, &id_b, base).await;
    schedule(&store_pb, &pb1, expires_at).await;

    let contained = store_pb
        .run_refund_worker_pass(future_scan)
        .await
        .expect("independent-keyspace refund pass");
    assert_eq!(
        contained, 1,
        "B's worker only sees B's own pending reservation"
    );
    assert_eq!(used(&store_pb, &id_b, future_scan).await, (0, 0));
    assert_eq!(
        used(&store_pa, &id_a, future_scan).await,
        (2, 2),
        "A's reservations are untouched by B's worker"
    );

    // A's own quota is still spent, so a third consumption is rejected on the
    // daily dimension.
    assert_eq!(
        store_pa
            .consume_with_limits_at(&id_a, limits(), future_scan)
            .await
            .expect("third consumption under A's limits"),
        QuotaConsumeResult::DailyExceeded,
        "A's quota survived B's worker"
    );

    // A's own worker can still refund A's two preserved reservations, which
    // proves B's pass operated on a different queue.
    assert_eq!(
        store_pa
            .run_refund_worker_pass(future_scan)
            .await
            .expect("A's own refund pass"),
        2
    );
    assert_eq!(used(&store_pa, &id_a, future_scan).await, (0, 0));
}
