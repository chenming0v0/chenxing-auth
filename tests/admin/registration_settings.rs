//! 公开注册开关（`registration` 设置）与注册闸门的集成测试。
//!
//! 覆盖契约：
//! - GET/PUT `/api/v1/admin/settings/registration`（AdminRead/AdminWrite + Owner-only ManageSystemSettings）
//! - 匿名 `GET /api/v1/auth/registration-status` 的有效值语义
//! - `POST /api/v1/users` 的新闸门顺序（开关 → 邮件验证要求 → 真实创建）

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

const ADMIN_TOKEN: &str = "registration-settings-token";
const SETTINGS_PATH: &str = "/api/v1/admin/settings/registration";
const STATUS_PATH: &str = "/api/v1/auth/registration-status";
const USERS_PATH: &str = "/api/v1/users";

async fn setup(configure_issuer: bool) -> (Router, sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("registration_settings", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("registration-settings");
    let mut config = if configure_issuer {
        Config::from_values_with_issuer(
            "127.0.0.1".to_owned(),
            3000,
            "http://127.0.0.1:3000".to_owned(),
            database_url,
            redis_url,
            3600,
        )
        .expect("config")
    } else {
        let mut config =
            Config::from_values("127.0.0.1".to_owned(), 3000, database_url, redis_url, 3600)
                .expect("config");
        config.issuer = None;
        config
    };
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

async fn put_setting(router: &Router, body: Value) -> (StatusCode, Value) {
    let response = send(
        router,
        Method::PUT,
        SETTINGS_PATH,
        Some(ADMIN_TOKEN),
        Some(body),
    )
    .await;
    let status = response.status();
    (status, json_body(response).await)
}

async fn registration_status(router: &Router) -> Value {
    let response = send(router, Method::GET, STATUS_PATH, None, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

/// 匿名引导首个 Owner；随后的用户 ID 偏移必须重新施加（与
/// `support/oauth_flow.rs::ensure_owner_bootstrapped` 同一理由）。
async fn bootstrap_owner(router: &Router, database: &sqlx::PgPool, suffix: &str) {
    let response = send(
        router,
        Method::POST,
        "/api/v1/admin/bootstrap",
        None,
        Some(json!({
            "username": format!("reg-owner-{suffix}"),
            "email": format!("reg-owner-{suffix}@example.com"),
            "password": "owner-password-123",
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    db_isolation::isolate_user_ids(database, "registration_settings").await;
}

async fn register_user(router: &Router, suffix: &str) -> axum::response::Response {
    send(
        router,
        Method::POST,
        USERS_PATH,
        None,
        Some(json!({
            "username": format!("reg-user-{suffix}"),
            "email": format!("reg-user-{suffix}@example.com"),
            "password": "user-password-123",
        })),
    )
    .await
}

#[tokio::test]
async fn registration_is_closed_by_default_and_reports_disabled() {
    let (router, _database, key_directory) = setup(true).await;

    // 管理读取：默认双 false。
    let response = send(&router, Method::GET, SETTINGS_PATH, Some(ADMIN_TOKEN), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["enabled"], false);
    assert_eq!(body["email_verification_required"], false);

    // 匿名状态端点：默认关闭。
    let status = registration_status(&router).await;
    assert_eq!(status["enabled"], false);
    assert_eq!(status["email_verification_required"], false);

    // 公开注册被开关闸门拒绝，先于任何输入校验与创建。
    let response = register_user(&router, &Uuid::new_v4().simple().to_string()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response).await["code"], "registration_disabled");

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_registration_endpoints_reject_anonymous_callers() {
    let (router, _database, key_directory) = setup(true).await;

    let response = send(&router, Method::GET, SETTINGS_PATH, None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = send(
        &router,
        Method::PUT,
        SETTINGS_PATH,
        None,
        Some(json!({
            "enabled": true,
            "email_verification_required": false,
            "invitation_code_required": false,
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn enabling_registration_without_issuer_is_rejected_and_status_stays_closed() {
    let (router, database, key_directory) = setup(false).await;

    let (status, body) = put_setting(
        &router,
        json!({
            "enabled": true,
            "email_verification_required": false,
            "invitation_code_required": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "issuer_not_configured");

    // 关闭方向不需要 Issuer。
    let (status, body) = put_setting(
        &router,
        json!({
            "enabled": false,
            "email_verification_required": false,
            "invitation_code_required": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["enabled"], false);

    // 即使绕过管理端点直接把「开启」写进库，匿名状态端点仍按有效值报关：
    // enabled = 存储值 AND Issuer 就绪。
    sqlx::query(
        "INSERT INTO app_settings (setting_key, setting_value, updated_at)
         VALUES ('registration', $1, NOW())
         ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value",
    )
    .bind(
        r#"{"enabled":true,"email_verification_required":false,"invitation_code_required":false}"#,
    )
    .execute(&database)
    .await
    .expect("persist registration setting");
    let status = registration_status(&router).await;
    assert_eq!(status["enabled"], false);
    assert_eq!(status["email_verification_required"], false);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn enabled_registration_creates_active_user_who_can_login() {
    let (router, database, key_directory) = setup(true).await;
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &database, &suffix).await;

    let (status, body) = put_setting(
        &router,
        json!({
            "enabled": true,
            "email_verification_required": false,
            "invitation_code_required": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["email_verification_required"], false);

    // 管理读取回显已保存设置；匿名状态端点报告有效值（Issuer 就绪 → 开）。
    let response = send(&router, Method::GET, SETTINGS_PATH, Some(ADMIN_TOKEN), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["enabled"], true);
    let status_body = registration_status(&router).await;
    assert_eq!(status_body["enabled"], true);
    assert_eq!(status_body["email_verification_required"], false);

    // 公开注册创建最低权限的 active 用户。
    let response = register_user(&router, &suffix).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response).await;
    assert_eq!(body["user"]["username"], format!("reg-user-{suffix}"));
    assert_eq!(body["user"]["role"], "user");
    assert_eq!(body["user"]["status"], "active");

    // 新用户可以用注册凭据登录。
    let response = send(
        &router,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({
            "identifier": format!("reg-user-{suffix}"),
            "password": "user-password-123",
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // 重复邮箱冲突。
    let response = register_user(&router, &suffix).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn email_verification_required_keeps_registration_fail_closed() {
    let (router, database, key_directory) = setup(true).await;
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &database, &suffix).await;

    let (status, body) = put_setting(
        &router,
        json!({
            "enabled": true,
            "email_verification_required": true,
            "invitation_code_required": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email_verification_required"], true);

    let status_body = registration_status(&router).await;
    assert_eq!(status_body["enabled"], true);
    assert_eq!(status_body["email_verification_required"], true);

    // 开关打开但要求邮件验证时，验证能力缺失保持 503 fail-closed。
    let response = register_user(&router, &suffix).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(response).await["code"],
        "email_verification_unavailable"
    );

    let _ = std::fs::remove_dir_all(key_directory);
}
