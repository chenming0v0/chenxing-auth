//! 注册邀请码批量创建、明细与停用的集成测试。
//!
//! 覆盖契约：
//! - POST/GET `/api/v1/admin/registration-invitation-codes`
//! - GET `/api/v1/admin/registration-invitation-codes/{id}`（使用记录 JOIN users）
//! - POST `/api/v1/admin/registration-invitation-codes/{id}/disable`
//! - 列表与明细永不返回明文 `code` 或摘要

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use chenxing_auth::{api, config::Config, sqlx, state::AppState};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{db_isolation, oauth_flow as key_directory};

const ADMIN_TOKEN: &str = "invitation-codes-token";
const CODES_PATH: &str = "/api/v1/admin/registration-invitation-codes";
const SETTINGS_PATH: &str = "/api/v1/admin/settings/registration";
const USERS_PATH: &str = "/api/v1/users";

async fn setup() -> (Router, sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("invitation_codes", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("invitation-codes");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = ADMIN_TOKEN.to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("state");
    state.worker_health.assume_ready_for_test();
    let router = api::router(state);
    (router, database, key_directory)
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON body")
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
    router
        .clone()
        .oneshot(request.body(body).expect("request"))
        .await
        .expect("response")
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
    (response.status(), json_body(response).await)
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
    }
    let first_id = created[0]["id"].as_i64().expect("first id");
    let second_id = created[1]["id"].as_i64().expect("second id");
    let first_code = created[0]["code"].as_str().expect("first code").to_owned();

    let response = send(&router, Method::GET, CODES_PATH, Some(ADMIN_TOKEN), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let listed = json_body(response).await;
    let listed = listed.as_array().expect("list");
    assert_eq!(listed.len(), 2);
    for item in listed {
        assert_no_secret_material(item);
        assert_eq!(item["label"], "batch-a");
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
    let unused = json_body(response).await;
    assert_no_secret_material(&unused);
    assert_eq!(unused["id"], first_id);
    assert_eq!(unused["label"], "batch-a");
    assert_eq!(unused["max_uses"], 3);
    assert_eq!(unused["use_count"], 0);
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
    let used = json_body(response).await;
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

    let response = send(
        &router,
        Method::GET,
        &detail_path(second_id),
        Some(ADMIN_TOKEN),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let still_unused = json_body(response).await;
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
    let disabled = json_body(response).await;
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
        json_body(response).await["code"],
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
