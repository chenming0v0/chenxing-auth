//! 注册邀请码批量创建、明细与停用的集成测试。
//!
//! 覆盖契约：
//! - POST/GET `/api/v1/admin/registration-invitation-codes`
//! - GET `/api/v1/admin/registration-invitation-codes/{id}`（使用记录 JOIN users）
//! - POST `/api/v1/admin/registration-invitation-codes/{id}/disable`
//! - 列表与明细永不返回明文 `code` 或摘要

use std::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use chenxing_auth::sqlx::{self, Connection, PgConnection};
use chenxing_auth::users::domain::ValidatedRegistration;
use chenxing_auth::users::email::EmailAddress;
use chenxing_auth::users::repository::{self, PublicUserInsertError};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::time::{sleep, timeout};
use uuid::Uuid;

use crate::{db_isolation, http};

const ADMIN_TOKEN: &str = "invitation-codes-token";
const CODES_PATH: &str = "/api/v1/admin/registration-invitation-codes";
const SETTINGS_PATH: &str = "/api/v1/admin/settings/registration";
const USERS_PATH: &str = "/api/v1/users";

async fn setup() -> (Router, sqlx::PgPool, std::path::PathBuf) {
    let (state, database, key_directory, _admin_token, _binary_name) =
        crate::harness::HarnessBuilder::new("invitation_codes")
            .admin_token(ADMIN_TOKEN)
            .build_state()
            .await;
    state.worker_health.assume_ready_for_test();
    (chenxing_auth::api::router(state), database, key_directory)
}

async fn send(
    router: &Router,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> axum::response::Response {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => {
            request = request.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    http::send(router, request.body(body).expect("request")).await
}

fn detail_path(id: i64) -> String {
    format!("{CODES_PATH}/{id}")
}

fn assert_no_secret_material(value: &Value) {
    assert!(value.get("code").is_none(), "{value}");
    assert!(value.get("code_digest").is_none(), "{value}");
    if let Some(uses) = value.get("uses").and_then(Value::as_array) {
        for entry in uses {
            assert!(entry.get("email").is_none(), "{entry}");
            assert!(entry.get("code").is_none(), "{entry}");
        }
    }
}

async fn bootstrap_owner(router: &Router, database: &sqlx::PgPool, suffix: &str) {
    let response = send(
        router,
        Method::POST,
        "/api/v1/admin/bootstrap",
        None,
        Some(json!({
            "username": format!("inv-owner-{suffix}"),
            "email": format!("inv-owner-{suffix}@example.com"),
            "password": "owner-password-123",
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    db_isolation::isolate_user_ids(database, "invitation_codes").await;
}

async fn create_batch(router: &Router, label: &str) -> (StatusCode, Value) {
    let response = send(
        router,
        Method::POST,
        CODES_PATH,
        Some(ADMIN_TOKEN),
        Some(json!({
            "count": 2,
            "max_uses": 3,
            "expires_at": null,
            "label": label,
        })),
    )
    .await;
    (response.status(), http::json_body(response).await)
}

#[tokio::test]
async fn invitation_code_detail_lists_uses_without_exposing_secrets() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &database, &suffix).await;

    let (status, created) = create_batch(&router, "batch-a").await;
    assert_eq!(status, StatusCode::CREATED);
    let created = created.as_array().expect("created batch");
    assert_eq!(created.len(), 2);
    for item in created {
        let code = item["code"].as_str().expect("plaintext code on create");
        assert!(code.starts_with("cxi_"), "{code}");
        assert_eq!(item["label"], "batch-a");
        assert_eq!(item["max_uses"], 3);
        assert_eq!(item["use_count"], 0);
        assert!(item["created_at"].as_str().is_some());
    }
    let first_id = created[0]["id"].as_i64().expect("first id");
    let second_id = created[1]["id"].as_i64().expect("second id");
    let first_code = created[0]["code"].as_str().expect("first code").to_owned();

    let response = send(&router, Method::GET, CODES_PATH, Some(ADMIN_TOKEN), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let listed = http::json_body(response).await;
    let listed = listed.as_array().expect("list");
    assert_eq!(listed.len(), 2);
    for item in listed {
        assert_no_secret_material(item);
        assert_eq!(item["label"], "batch-a");
        assert!(item["created_at"].as_str().is_some());
    }

    let response = send(
        &router,
        Method::GET,
        &detail_path(first_id),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let unused = http::json_body(response).await;
    assert_no_secret_material(&unused);
    assert_eq!(unused["id"], first_id);
    assert_eq!(unused["label"], "batch-a");
    assert_eq!(unused["max_uses"], 3);
    assert_eq!(unused["use_count"], 0);
    assert!(unused["created_at"].as_str().is_some());
    assert_eq!(unused["uses"], json!([]));

    let response = send(
        &router,
        Method::PUT,
        SETTINGS_PATH,
        Some(ADMIN_TOKEN),
        Some(json!({
            "enabled": true,
            "email_verification_required": false,
            "invitation_code_required": true,
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let first_username = format!("inv-user-a-{suffix}");
    let second_username = format!("inv-user-b-{suffix}");
    let response = send(
        &router,
        Method::POST,
        USERS_PATH,
        None,
        Some(json!({
            "username": first_username,
            "email": format!("{first_username}@example.com"),
            "password": "user-password-123",
            "display_name": "Alice",
            "invitation_code": first_code,
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = send(
        &router,
        Method::POST,
        USERS_PATH,
        None,
        Some(json!({
            "username": second_username,
            "email": format!("{second_username}@example.com"),
            "password": "user-password-123",
            "display_name": "Bob",
            "invitation_code": first_code,
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = send(
        &router,
        Method::GET,
        &detail_path(first_id),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let used = http::json_body(response).await;
    assert_no_secret_material(&used);
    assert_eq!(used["use_count"], 2);
    let uses = used["uses"].as_array().expect("uses");
    assert_eq!(uses.len(), 2);
    assert_eq!(uses[0]["username"], second_username);
    assert_eq!(uses[0]["display_name"], "Bob");
    assert_eq!(uses[1]["username"], first_username);
    assert_eq!(uses[1]["display_name"], "Alice");
    let later_user_id = uses[0]["user_id"].as_i64().expect("later user id");
    let earlier_user_id = uses[1]["user_id"].as_i64().expect("earlier user id");
    assert!(later_user_id > earlier_user_id);
    assert!(uses[0]["used_at"].as_str().is_some());
    assert!(uses[1]["used_at"].as_str().is_some());
    assert!(used["created_at"].as_str().is_some());

    let response = send(
        &router,
        Method::GET,
        &detail_path(second_id),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let still_unused = http::json_body(response).await;
    assert_eq!(still_unused["use_count"], 0);
    assert_eq!(still_unused["uses"], json!([]));

    let response = send(
        &router,
        Method::POST,
        &format!("{}/disable", detail_path(first_id)),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let disabled = http::json_body(response).await;
    assert_no_secret_material(&disabled);
    assert_eq!(disabled["id"], first_id);
    assert!(disabled["disabled_at"].as_str().is_some());

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn invitation_code_detail_returns_not_found_for_unknown_id() {
    let (router, _database, key_directory) = setup().await;

    let response = send(
        &router,
        Method::GET,
        &detail_path(999_999),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        http::json_body(response).await["code"],
        "invitation_code_not_found"
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn invitation_code_detail_rejects_unauthenticated() {
    let (router, _database, key_directory) = setup().await;

    let response = send(&router, Method::GET, &detail_path(1), None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let _ = std::fs::remove_dir_all(key_directory);
}

/// Issue #730: `NOW()` is pinned at `BEGIN`. The owner-bootstrap lock is taken
/// before the expiry read. Dial the code into the window after that begin and
/// before the read; registration must not consume it.
#[tokio::test]
async fn invitation_expiring_during_owner_lock_does_not_register() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &database, &suffix).await;
    let code = format!("cxi-{suffix}");
    let digest = chenxing_auth::invitation_codes::digest(&code);
    let invitation_id: i64 = sqlx::query_scalar(
        "INSERT INTO registration_invitation_codes (code_digest, max_uses, expires_at)
         VALUES ($1, 1, statement_timestamp() + interval '1 day')
         RETURNING id",
    )
    .bind(digest.as_slice())
    .fetch_one(&database)
    .await
    .expect("insert invitation");

    let mut blocker = database.begin().await.expect("begin owner lock");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .expect("blocker pid");
    // Matches `BusinessLock::OwnerBootstrap` (namespace 0).
    sqlx::query("SELECT pg_advisory_xact_lock($1::integer, $2::integer)")
        .bind(0_i32)
        .bind(7_341_928_i32)
        .execute(&mut *blocker)
        .await
        .expect("lock owner bootstrap");

    let pool = database.clone();
    let username = format!("inv-exp-{suffix}");
    let email = format!("{username}@example.com");
    let registration = ValidatedRegistration {
        username: username.clone(),
        email: EmailAddress::parse(&email).expect("email"),
        password: "unused-password".to_owned(),
        display_name: None,
    };
    let task = tokio::spawn(async move {
        repository::insert_public_user(
            &pool,
            registration,
            "not-a-real-hash".to_owned(),
            Some(&digest),
        )
        .await
    });
    wait_for_owner_lock(blocker_pid).await;
    let dialled = sqlx::query(
        "UPDATE registration_invitation_codes
         SET expires_at = statement_timestamp()
         WHERE id = $1",
    )
    .bind(invitation_id)
    .execute(&mut *blocker)
    .await
    .expect("dial invitation expiry")
    .rows_affected();
    assert_eq!(dialled, 1);
    let waiter_started: OffsetDateTime = sqlx::query_scalar(
        "SELECT xact_start FROM pg_stat_activity
         WHERE $1 = ANY(pg_blocking_pids(pid))
         LIMIT 1",
    )
    .bind(blocker_pid)
    .fetch_one(&mut *blocker)
    .await
    .expect("waiting transaction start");
    let expires_at: OffsetDateTime =
        sqlx::query_scalar("SELECT expires_at FROM registration_invitation_codes WHERE id = $1")
            .bind(invitation_id)
            .fetch_one(&mut *blocker)
            .await
            .expect("dialled expiry");
    assert!(
        expires_at > waiter_started,
        "dialled expiry {expires_at} must stay after the registration transaction begin {waiter_started}"
    );
    blocker.commit().await.expect("release owner lock");

    let result = task.await.expect("register task");
    assert!(
        matches!(result, Err(PublicUserInsertError::InvalidInvitation)),
        "got {result:?}"
    );
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1")
        .bind(&username)
        .fetch_one(&database)
        .await
        .expect("user count");
    assert_eq!(users, 0);
    let use_count: i32 =
        sqlx::query_scalar("SELECT use_count FROM registration_invitation_codes WHERE id = $1")
            .bind(invitation_id)
            .fetch_one(&database)
            .await
            .expect("use count");
    assert_eq!(use_count, 0);
    let uses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM registration_invitation_uses WHERE invitation_id = $1",
    )
    .bind(invitation_id)
    .fetch_one(&database)
    .await
    .expect("invitation uses");
    assert_eq!(uses, 0);

    let _ = std::fs::remove_dir_all(key_directory);
}

/// Issue #730: the use-count update repeats the expiry predicate. An already
/// expired row changes zero rows, and a user inserted in that transaction
/// rolls back with it.
#[tokio::test]
async fn expired_invitation_consume_updates_zero_rows_and_rolls_back() {
    let (_router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let invitation_id: i64 = sqlx::query_scalar(
        "INSERT INTO registration_invitation_codes
            (code_digest, max_uses, created_at, expires_at)
         VALUES ($1, 1,
                 statement_timestamp() - interval '2 minutes',
                 statement_timestamp() - interval '1 second')
         RETURNING id",
    )
    .bind(chenxing_auth::invitation_codes::digest(&format!("cxi-expired-{suffix}")).as_slice())
    .fetch_one(&database)
    .await
    .expect("insert expired invitation");

    let username = format!("inv-rollback-{suffix}");
    let email = format!("{username}@example.com");
    let mut tx = database.begin().await.expect("begin");
    let user_id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, role, status)
         VALUES ($1, $2, lower($2), 'hash', 'user', 'active')
         RETURNING id",
    )
    .bind(&username)
    .bind(&email)
    .fetch_one(&mut *tx)
    .await
    .expect("provisional user");
    let consumed = repository::consume_invitation_use(&mut tx, invitation_id)
        .await
        .expect("consume invitation");
    assert!(!consumed);
    let use_count: i32 =
        sqlx::query_scalar("SELECT use_count FROM registration_invitation_codes WHERE id = $1")
            .bind(invitation_id)
            .fetch_one(&mut *tx)
            .await
            .expect("use count");
    assert_eq!(use_count, 0);
    tx.rollback().await.expect("rollback");

    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&database)
        .await
        .expect("rolled back user");
    assert_eq!(users, 0);
    let uses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM registration_invitation_uses WHERE invitation_id = $1",
    )
    .bind(invitation_id)
    .fetch_one(&database)
    .await
    .expect("invitation uses");
    assert_eq!(uses, 0);

    let _ = std::fs::remove_dir_all(key_directory);
}

async fn wait_for_owner_lock(blocker_pid: i32) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let mut observer = PgConnection::connect(&database_url)
        .await
        .expect("connect lock observer");
    timeout(Duration::from_secs(15), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM pg_stat_activity
                     WHERE $1 = ANY(pg_blocking_pids(pid))
                 )",
            )
            .bind(blocker_pid)
            .fetch_one(&mut observer)
            .await
            .expect("inspect lock wait");
            if blocked {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("registration never reached the owner bootstrap lock");
}
