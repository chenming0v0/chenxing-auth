//! #748：真实 PostgreSQL 锁等待跨过到期后，创建和幂等创建必须采用默认额度。

use std::time::Duration;

use chenxing_auth::clients::{
    idempotency::IdempotencyKey,
    service::{ClientServiceError, RegisteredOwnedClient},
};
use tokio::{task::JoinHandle, time::timeout};

mod fixtures;
mod waiting;

use fixtures::{Fixture, PAID_DAILY_LIMIT, audit, default_auth_limits, registration};
use waiting::{WaitAt, block_for_expiry, wait_past_expiry};

fn start_create(
    fixture: &Fixture,
) -> JoinHandle<Result<Option<RegisteredOwnedClient>, ClientServiceError>> {
    let clients = fixture.env.state.clients.clone();
    let user_id = fixture.user_id;
    tokio::spawn(async move {
        clients
            .register_for_user_with_audit(user_id, registration("waited"), move |client| {
                audit(user_id, client)
            })
            .await
    })
}

async fn reject_after_wait(wait_at: WaitAt) {
    let fixture = Fixture::new(Some(1), true).await;
    let (blocker, pid) = block_for_expiry(&fixture, wait_at).await;
    let task = start_create(&fixture);
    wait_past_expiry(&fixture, pid, wait_at).await;
    blocker.commit().await.expect("release blocker");
    let result = timeout(Duration::from_secs(15), task)
        .await
        .expect("creation timed out")
        .expect("creation task panicked");
    assert!(
        matches!(&result, Err(ClientServiceError::QuotaExceeded)),
        "{result:?}"
    );
    fixture.assert_effects(1, 0).await;
    fixture.env.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_row_wait_cannot_spend_expired_paid_quota() {
    reject_after_wait(WaitAt::UserRow).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_plan_lock_wait_cannot_spend_expired_paid_quota() {
    reject_after_wait(WaitAt::DefaultSet).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn assigned_plan_row_wait_cannot_spend_expired_paid_quota() {
    reject_after_wait(WaitAt::PlanRow).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quota_count_wait_rechecks_expiry_at_insert() {
    reject_after_wait(WaitAt::QuotaCount).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_after_plan_resolution_can_use_available_default_quota() {
    let fixture = Fixture::new(Some(1), false).await;
    let (blocker, pid) = block_for_expiry(&fixture, WaitAt::QuotaCount).await;
    let task = start_create(&fixture);
    wait_past_expiry(&fixture, pid, WaitAt::QuotaCount).await;
    blocker.commit().await.expect("release count blocker");
    let created = timeout(Duration::from_secs(15), task)
        .await
        .expect("creation timed out")
        .expect("creation task panicked")
        .expect("default quota permits creation")
        .expect("default plan remains active");
    assert_eq!(created.quota_limits, default_auth_limits());
    fixture.assert_effects(1, 1).await;
    fixture.env.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_at_insert_without_default_keeps_self_service_closed() {
    let fixture = Fixture::new(None, false).await;
    let (blocker, pid) = block_for_expiry(&fixture, WaitAt::QuotaCount).await;
    let task = start_create(&fixture);
    wait_past_expiry(&fixture, pid, WaitAt::QuotaCount).await;
    blocker.commit().await.expect("release count blocker");
    let result = timeout(Duration::from_secs(15), task)
        .await
        .expect("creation timed out")
        .expect("creation task panicked");
    assert!(matches!(&result, Ok(None)), "{result:?}");
    fixture.assert_effects(0, 0).await;
    fixture.env.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idempotency_claim_wait_cannot_spend_expired_paid_quota() {
    let fixture = Fixture::new(Some(1), true).await;
    let (blocker, pid) = block_for_expiry(&fixture, WaitAt::IdempotencyClaim).await;
    let user_id = fixture.user_id;
    let clients = fixture.env.state.clients.clone();
    let task = tokio::spawn(async move {
        clients
            .register_for_user_with_audit_idempotent(
                user_id,
                registration("expired-claim"),
                format!("user:{user_id}"),
                IdempotencyKey::parse("expired-claim").expect("idempotency key"),
                move |client| audit(user_id, client),
            )
            .await
    });
    wait_past_expiry(&fixture, pid, WaitAt::IdempotencyClaim).await;
    blocker.commit().await.expect("release claim blocker");
    let result = timeout(Duration::from_secs(15), task)
        .await
        .expect("creation timed out")
        .expect("creation task panicked");
    assert!(
        matches!(&result, Err(ClientServiceError::QuotaExceeded)),
        "{result:?}"
    );
    fixture.assert_effects(1, 0).await;
    let claims: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM client_operation_idempotency")
            .fetch_one(&fixture.env.database)
            .await
            .expect("count rolled-back claims");
    assert_eq!(claims, 0);
    fixture.env.cleanup().await;
}

#[tokio::test]
async fn unexpired_and_archived_assignments_keep_their_existing_fallback_behavior() {
    let fixture = Fixture::new(Some(2), false).await;
    let created = fixture
        .env
        .state
        .clients
        .register_for_user(fixture.user_id, registration("paid"))
        .await
        .expect("paid quota permits creation")
        .expect("assigned plan");
    assert_eq!(created.quota_limits.daily_auth_limit, PAID_DAILY_LIMIT);
    assert_eq!(created.quota_limits.monthly_auth_limit, Some(9_000));
    chenxing_auth::sqlx::query("UPDATE plans SET status = 'archived' WHERE id = $1")
        .bind(fixture.plan_id)
        .execute(&fixture.env.database)
        .await
        .expect("archive paid plan");
    let created = fixture
        .env
        .state
        .clients
        .register_for_user(fixture.user_id, registration("default"))
        .await
        .expect("default quota permits creation")
        .expect("fallback plan");
    assert_eq!(created.quota_limits, default_auth_limits());
    fixture.assert_effects(2, 0).await;
    fixture.env.cleanup().await;
}
