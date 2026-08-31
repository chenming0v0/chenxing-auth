use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::{
    audit::{AuditAction, AuditEvent},
    plans::addons::{QuotaAddonError, QuotaAddonPurchaseInput},
    users::UserSessionCredential,
    wallet::{
        domain::PurchaseInput, redemption_service::RedemptionError, service::WalletServiceError,
    },
};
use serde_json::Value;
use std::{sync::Arc, time::Duration as StdDuration};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::sync::Barrier;
use tokio::time::{sleep, timeout};
use tower::ServiceExt;
use uuid::Uuid;

use crate::plans_support as support;
use support::{
    ADMIN_TOKEN, bootstrap_owner, create_plan, json, persisted_user_session,
    persisted_user_session_with_ttl, plan_limits, register_user, test_state, user_session,
};

async fn get_wallet(router: &axum::Router, cookie: Option<&str>) -> (StatusCode, Option<Value>) {
    let mut builder = Request::builder().uri("/api/v1/auth/wallet");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let response = router
        .clone()
        .oneshot(builder.body(Body::empty()).expect("wallet request"))
        .await
        .expect("wallet response");
    let status = response.status();
    if status == StatusCode::OK {
        (status, Some(json(response).await))
    } else {
        (status, None)
    }
}

async fn list_ledger(router: &axum::Router, cookie: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/wallet/ledger?page=1&page_size=20")
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("ledger request"),
        )
        .await
        .expect("ledger response");
    let status = response.status();
    (status, json(response).await)
}

async fn credit_wallet(
    router: &axum::Router,
    user_id: i64,
    amount: i64,
    note: Option<&str>,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/wallet/credit"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "amount": amount, "note": note }).to_string(),
                ))
                .expect("credit request"),
        )
        .await
        .expect("credit response");
    let status = response.status();
    (status, json(response).await)
}

async fn purchase_plan(
    router: &axum::Router,
    cookie: &str,
    csrf: &str,
    plan_id: i64,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/wallet/purchase")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "plan_id": plan_id }).to_string(),
                ))
                .expect("purchase request"),
        )
        .await
        .expect("purchase response");
    let status = response.status();
    (status, json(response).await)
}

async fn user_plan(
    database: &chenxing_auth::sqlx::PgPool,
    user_id: i64,
) -> (Option<i64>, Option<OffsetDateTime>) {
    chenxing_auth::sqlx::query_as("SELECT plan_id, plan_expires_at FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("user plan")
}

fn priced_plan_limits(price_points: i64, billing_period: &str) -> serde_json::Map<String, Value> {
    let mut limits = plan_limits(2, 2500, Some(50_000), None);
    limits.insert("price_points".to_owned(), Value::from(price_points));
    limits.insert(
        "billing_period".to_owned(),
        Value::String(billing_period.to_owned()),
    );
    limits
}

fn wallet_audit(user_id: i64, action: AuditAction, resource_type: &str) -> AuditEvent {
    AuditEvent::new(
        "user".to_owned(),
        Some(user_id.to_string()),
        action,
        resource_type.to_owned(),
        Some(user_id.to_string()),
        serde_json::json!({"result": "success"}),
    )
}

async fn wait_for_database_block(database: &chenxing_auth::sqlx::PgPool, blocker_pid: i32) {
    timeout(StdDuration::from_secs(5), async {
        loop {
            let blocked: bool = chenxing_auth::sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1
                     FROM pg_stat_activity
                     WHERE $1 = ANY(pg_blocking_pids(pid))
                 )",
            )
            .bind(blocker_pid)
            .fetch_one(database)
            .await
            .expect("inspect PostgreSQL lock wait");
            if blocked {
                return;
            }
            sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("wallet mutation never reached the user row lock");
}

#[tokio::test]
async fn fresh_wallet_reads_as_zero_without_a_row() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, _) = user_session(&env.state, user_id).await;

    let (status, body) = get_wallet(&router, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    let body = body.expect("wallet json");
    assert_eq!(body["balance"], 0);
    assert_eq!(body["currency"], "points");

    let exists: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_wallets WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&env.database)
    .await
    .expect("wallet existence");
    assert!(!exists, "GET must not insert a lazy wallet row");

    env.cleanup().await;
}

#[tokio::test]
async fn unauthenticated_wallet_read_is_rejected() {
    let env = test_state().await;
    let router = env.router();
    let (status, _) = get_wallet(&router, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    env.cleanup().await;
}

#[tokio::test]
async fn admin_credit_creates_wallet_and_ledger_row() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, _) = user_session(&env.state, user_id).await;

    let (status, body) = credit_wallet(&router, user_id, 100, Some("活动赠送")).await;
    assert_eq!(status, StatusCode::OK, "credit: {body}");
    assert_eq!(body["user_id"], user_id);
    assert_eq!(body["balance"], 100);

    let (status, wallet) = get_wallet(&router, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(wallet.expect("wallet")["balance"], 100);

    let (status, ledger) = list_ledger(&router, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ledger["total"], 1);
    assert_eq!(ledger["page"], 1);
    assert_eq!(ledger["page_size"], 20);
    assert_eq!(ledger["items"][0]["amount"], 100);
    assert_eq!(ledger["items"][0]["balance_after"], 100);
    assert_eq!(ledger["items"][0]["kind"], "credit");
    assert_eq!(ledger["items"][0]["note"], "活动赠送");

    let missing = credit_wallet(&router, user_id + 1_000_000, 10, None).await;
    assert_eq!(missing.0, StatusCode::NOT_FOUND);
    assert_eq!(missing.1["code"], "user_not_found");

    env.cleanup().await;
}

#[tokio::test]
async fn purchase_debits_wallet_and_assigns_plan_period() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let plan = create_plan(
        &router,
        &format!("paid-{suffix}"),
        priced_plan_limits(40, "monthly"),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(plan["price_points"], 40);
    assert_eq!(plan["billing_period"], "monthly");

    let (status, _) = credit_wallet(&router, user_id, 100, None).await;
    assert_eq!(status, StatusCode::OK);

    let before = OffsetDateTime::now_utc();
    let (status, body) = purchase_plan(&router, &cookie, &csrf, plan_id).await;
    let after = OffsetDateTime::now_utc();
    assert_eq!(status, StatusCode::OK, "purchase: {body}");
    assert_eq!(body["balance"], 60);
    assert_eq!(body["plan_id"], plan_id);
    let expires = OffsetDateTime::parse(
        body["plan_expires_at"].as_str().expect("expires_at"),
        &Rfc3339,
    )
    .expect("rfc3339 expires_at");
    let expected_min = before + Duration::days(30) - Duration::seconds(5);
    let expected_max = after + Duration::days(30) + Duration::seconds(5);
    assert!(
        expires >= expected_min && expires <= expected_max,
        "monthly expiry {expires} not near now+30d"
    );

    let (assigned_plan, assigned_expiry) = user_plan(&env.database, user_id).await;
    assert_eq!(assigned_plan, Some(plan_id));
    assert!(assigned_expiry.is_some());

    let (status, wallet) = get_wallet(&router, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(wallet.expect("wallet")["balance"], 60);

    let (_, ledger) = list_ledger(&router, &cookie).await;
    let purchase = ledger["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["kind"] == "purchase")
        .expect("purchase ledger row");
    assert_eq!(purchase["amount"], -40);
    assert_eq!(purchase["balance_after"], 60);
    assert_eq!(purchase["reference_type"], "plan");
    assert_eq!(purchase["reference_id"], plan_id.to_string());

    env.cleanup().await;
}

#[tokio::test]
async fn purchase_with_insufficient_balance_is_a_no_op() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;
    let (previous_plan, previous_expiry) = user_plan(&env.database, user_id).await;

    let plan = create_plan(
        &router,
        &format!("rich-{suffix}"),
        priced_plan_limits(100, "one_time"),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    let (status, _) = credit_wallet(&router, user_id, 40, None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = purchase_plan(&router, &cookie, &csrf, plan_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "insufficient_balance");

    let (status, wallet) = get_wallet(&router, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(wallet.expect("wallet")["balance"], 40);
    let (assigned_plan, assigned_expiry) = user_plan(&env.database, user_id).await;
    assert_eq!(assigned_plan, previous_plan);
    assert_eq!(assigned_expiry, previous_expiry);

    env.cleanup().await;
}

#[tokio::test]
async fn price_zero_plan_is_not_purchasable() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let plan = create_plan(
        &router,
        &format!("free-{suffix}"),
        plan_limits(2, 10, None, None),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(plan["price_points"], 0);
    let (status, _) = credit_wallet(&router, user_id, 100, None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = purchase_plan(&router, &cookie, &csrf, plan_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "plan_not_purchasable");

    let (status, wallet) = get_wallet(&router, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(wallet.expect("wallet")["balance"], 100);

    env.cleanup().await;
}

#[tokio::test]
async fn concurrent_purchases_cannot_drive_balance_negative() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let plan = create_plan(
        &router,
        &format!("race-{suffix}"),
        priced_plan_limits(100, "one_time"),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    let (status, _) = credit_wallet(&router, user_id, 100, None).await;
    assert_eq!(status, StatusCode::OK);

    let start = Arc::new(Barrier::new(2));
    let first = {
        let router = router.clone();
        let cookie = cookie.clone();
        let csrf = csrf.clone();
        let start = Arc::clone(&start);
        async move {
            start.wait().await;
            purchase_plan(&router, &cookie, &csrf, plan_id).await
        }
    };
    let second = {
        let router = router.clone();
        let cookie = cookie.clone();
        let csrf = csrf.clone();
        let start = Arc::clone(&start);
        async move {
            start.wait().await;
            purchase_plan(&router, &cookie, &csrf, plan_id).await
        }
    };
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first, second];
    let successes = outcomes
        .iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .count();
    let insufficient = outcomes
        .iter()
        .filter(|(status, body)| {
            *status == StatusCode::BAD_REQUEST && body["code"] == "insufficient_balance"
        })
        .count();
    assert_eq!(successes, 1, "outcomes: {outcomes:?}");
    assert_eq!(insufficient, 1, "outcomes: {outcomes:?}");

    let (status, wallet) = get_wallet(&router, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(wallet.expect("wallet")["balance"], 0);
    let balance: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT balance FROM user_wallets WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&env.database)
            .await
            .expect("persisted balance");
    assert_eq!(balance, 0);
    let (assigned_plan, _) = user_plan(&env.database, user_id).await;
    assert_eq!(assigned_plan, Some(plan_id));

    env.cleanup().await;
}

/// Issue #704: the request-entry snapshot must not authorize any asset or
/// entitlement mutation after the exact Session row has been revoked.
#[tokio::test]
async fn revoked_session_proof_is_rejected_by_every_wallet_side_effect_boundary() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let session = persisted_user_session(&env.state, user_id).await;
    let credential =
        UserSessionCredential::from_session(user_id, &session).expect("persisted credential");

    let plan = create_plan(
        &router,
        &format!("revoked-{suffix}"),
        priced_plan_limits(40, "monthly"),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    let (status, _) = credit_wallet(&router, user_id, 100, None).await;
    assert_eq!(status, StatusCode::OK);

    let mut user_lock = env.database.begin().await.expect("begin user lock");
    let blocker_pid: i32 = chenxing_auth::sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *user_lock)
        .await
        .expect("user lock backend pid");
    chenxing_auth::sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut *user_lock)
        .await
        .expect("lock wallet user");

    let wallets = env.state.wallets.clone();
    let purchase_task = tokio::spawn(async move {
        wallets
            .purchase(
                credential,
                PurchaseInput { plan_id },
                wallet_audit(user_id, AuditAction::PlanPurchase, "user"),
            )
            .await
    });
    wait_for_database_block(&env.database, blocker_pid).await;
    env.state
        .sessions
        .revoke(&session.token)
        .await
        .expect("revoke captured session after request entry");
    user_lock.commit().await.expect("release wallet user lock");

    let purchase = purchase_task.await.expect("wallet purchase task");
    assert!(matches!(purchase, Err(WalletServiceError::SessionInvalid)));

    let addon = env
        .state
        .wallets
        .purchase_quota_addon(
            credential,
            QuotaAddonPurchaseInput { addon_id: 1 },
            wallet_audit(user_id, AuditAction::QuotaAddonPurchase, "user"),
        )
        .await;
    assert!(matches!(addon, Err(QuotaAddonError::SessionInvalid)));

    let redemption = env
        .state
        .redemptions
        .redeem(
            credential,
            "cxp_123456789012",
            wallet_audit(
                user_id,
                AuditAction::WalletRedemption,
                "wallet_redemption_code",
            ),
        )
        .await;
    assert!(matches!(redemption, Err(RedemptionError::SessionInvalid)));

    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT balance FROM user_wallets WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&env.database)
        .await
        .expect("wallet balance"),
        100
    );
    assert_eq!(user_plan(&env.database, user_id).await, (None, None));
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM wallet_ledger WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&env.database)
        .await
        .expect("wallet ledger count"),
        1,
        "only the administrative credit may be recorded"
    );

    env.cleanup().await;
}

/// Account status is re-read under the user-generation lock. A proof captured
/// while the account was active must not debit the wallet after disablement.
#[tokio::test]
async fn disabled_user_is_rejected_before_plan_purchase_side_effects() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let session = persisted_user_session(&env.state, user_id).await;
    let credential =
        UserSessionCredential::from_session(user_id, &session).expect("persisted credential");
    let plan = create_plan(
        &router,
        &format!("disabled-{suffix}"),
        priced_plan_limits(40, "monthly"),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    let (status, _) = credit_wallet(&router, user_id, 100, None).await;
    assert_eq!(status, StatusCode::OK);

    chenxing_auth::sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
        .bind(user_id)
        .execute(&env.database)
        .await
        .expect("disable user");

    let purchase = env
        .state
        .wallets
        .purchase(
            credential,
            PurchaseInput { plan_id },
            wallet_audit(user_id, AuditAction::PlanPurchase, "user"),
        )
        .await;
    assert!(matches!(purchase, Err(WalletServiceError::UserDisabled)));
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT balance FROM user_wallets WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&env.database)
        .await
        .expect("wallet balance"),
        100
    );
    assert_eq!(user_plan(&env.database, user_id).await, (None, None));

    env.cleanup().await;
}

/// PostgreSQL `NOW()` is fixed at transaction start. The final fence must use a
/// fresh statement timestamp after resource-lock waits, or an expired Session
/// could still debit the wallet.
#[tokio::test]
async fn session_expiry_while_waiting_for_plan_lock_prevents_purchase() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let plan = create_plan(
        &router,
        &format!("expiry-{suffix}"),
        priced_plan_limits(40, "monthly"),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    let (status, _) = credit_wallet(&router, user_id, 100, None).await;
    assert_eq!(status, StatusCode::OK);
    let session =
        persisted_user_session_with_ttl(&env.state, user_id, StdDuration::from_secs(2)).await;
    let credential =
        UserSessionCredential::from_session(user_id, &session).expect("persisted credential");

    let mut plan_lock = env.database.begin().await.expect("begin plan lock");
    let blocker_pid: i32 = chenxing_auth::sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *plan_lock)
        .await
        .expect("plan lock backend pid");
    chenxing_auth::sqlx::query("SELECT id FROM plans WHERE id = $1 FOR UPDATE")
        .bind(plan_id)
        .fetch_one(&mut *plan_lock)
        .await
        .expect("lock purchased plan");

    let wallets = env.state.wallets.clone();
    let purchase_task = tokio::spawn(async move {
        wallets
            .purchase(
                credential,
                PurchaseInput { plan_id },
                wallet_audit(user_id, AuditAction::PlanPurchase, "user"),
            )
            .await
    });
    wait_for_database_block(&env.database, blocker_pid).await;
    sleep(StdDuration::from_secs(3)).await;
    plan_lock
        .commit()
        .await
        .expect("release purchased plan lock");

    assert!(matches!(
        purchase_task.await.expect("wallet purchase task"),
        Err(WalletServiceError::SessionInvalid)
    ));
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT balance FROM user_wallets WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&env.database)
        .await
        .expect("wallet balance"),
        100
    );
    assert_eq!(user_plan(&env.database, user_id).await, (None, None));

    env.cleanup().await;
}
