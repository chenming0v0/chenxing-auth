#![allow(dead_code)]

//! `tests/plans.rs` 的脚手架：状态构造、HTTP 辅助和套餐前提。
//!
//! 每个测试的套餐前提**写在测试里**：[`test_state`] 只保证一个已知的起点
//! （清空 + 播种原种子等价的默认套餐），需要「没有套餐」的测试自己调
//! [`clear_all_plans`]。

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD};
use chenxing_auth::{
    api, config::Config, oauth::authorization::ValidatedAuthorizationRequest,
    sessions::domain::Session, state::AppState,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "plan_fixtures.rs"]
pub mod fixtures;

pub use fixtures::{
    DEFAULT_PLAN_CODE, active_default_plan_count, clear_all_plans, plan_status_and_default,
    seed_default_plan,
};

pub const ADMIN_TOKEN: &str = "plans-admin-token";
pub const REDIRECT_URI: &str = "https://plan.example/callback";

/// 一个套餐测试的运行环境。
///
/// 套餐前提由 schema 隔离保证（见 `support/db_isolation.rs`）：`plans` 表存在于
/// 本二进制私有的 schema 中，`clear_all_plans` 只影响自己，不需要跨二进制锁。
/// `default_plan_id` 是 [`test_state`] 播种的默认套餐 id，不把 identity 序列值当作
/// 测试契约。
pub struct PlanTestEnv {
    pub state: AppState,
    pub database: chenxing_auth::sqlx::PgPool,
    pub key_directory: std::path::PathBuf,
    pub default_plan_id: i64,
}

impl PlanTestEnv {
    pub fn router(&self) -> Router {
        api::router(self.state.clone())
    }

    /// 删除测试创建的套餐和专用密钥目录。测试结尾调用。
    pub async fn cleanup(&self) {
        clear_all_plans(&self.database).await;
        let _ = std::fs::remove_dir_all(&self.key_directory);
    }
}

/// 构造测试状态，并把套餐前提重置为「只有一个原种子等价的 active 默认套餐」。
///
/// 即使迁移提供了种子，这里仍显式清空后播种；需要「没有任何套餐」的测试在拿到
/// 环境后自己调 [`clear_all_plans`]。
pub async fn test_state() -> PlanTestEnv {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = crate::db_isolation::isolated_pool("plans", &database_url).await;
    clear_all_plans(&database).await;
    let default_plan_id = seed_default_plan(&database).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-plans-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.admin_token = ADMIN_TOKEN.to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state");
    PlanTestEnv {
        state,
        database,
        key_directory,
        default_plan_id,
    }
}

pub async fn json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

pub async fn bootstrap_owner(router: &Router, suffix: &str) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("plan-owner-{suffix}"),
                        "email": format!("plan-owner-{suffix}@example.com"),
                        "password": "correct horse battery",
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert!(
        matches!(
            response.status(),
            StatusCode::CREATED | StatusCode::CONFLICT
        ),
        "unexpected bootstrap status: {}",
        response.status()
    );
}

pub async fn register_user(router: &Router, suffix: &str) -> i64 {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("plan-user-{suffix}"),
                        "email": format!("plan-user-{suffix}@example.com"),
                        "password": "correct horse battery",
                    })
                    .to_string(),
                ))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::CREATED);
    json(response).await["user"]["id"]
        .as_i64()
        .expect("numeric user id")
}

pub async fn user_session(state: &AppState, user_id: i64) -> (String, String) {
    let mut session =
        Session::new(user_id.to_string(), Duration::from_secs(3600)).expect("browser session");
    state
        .sessions
        .save(&mut session, Duration::from_secs(3600))
        .await
        .expect("persist session");
    let cookie = format!(
        "chenxing_session={}; chenxing_csrf={}",
        session.token, session.csrf_token
    );
    (cookie, session.csrf_token)
}

/// 发起自助创建 Client 的请求，返回原始响应（用于断言 403 等失败状态）。
pub async fn post_owned_client(
    router: &Router,
    cookie: &str,
    csrf: &str,
    suffix: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": format!("Plan Client {suffix}"),
                        "redirect_uris": [REDIRECT_URI],
                        "scopes": ["openid", "profile", "email"],
                    })
                    .to_string(),
                ))
                .expect("owned client request"),
        )
        .await
        .expect("owned client response")
}

pub async fn create_owned_client(router: &Router, cookie: &str, csrf: &str, suffix: &str) -> Value {
    let response = post_owned_client(router, cookie, csrf, suffix).await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "owned client creation: {}",
        response.status()
    );
    json(response).await
}

/// 通过管理接口创建 Client：`owner_user_id IS NULL`，不受套餐计量影响。
pub async fn create_admin_client(router: &Router, suffix: &str) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": format!("Admin Client {suffix}"),
                        "redirect_uris": [REDIRECT_URI],
                        "scopes": ["openid", "profile", "email"],
                    })
                    .to_string(),
                ))
                .expect("admin client request"),
        )
        .await
        .expect("admin client response");
    assert_eq!(response.status(), StatusCode::CREATED, "admin client");
    json(response).await
}

pub async fn create_plan(
    router: &Router,
    suffix: &str,
    limits: serde_json::Map<String, Value>,
) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("code".to_owned(), Value::String(format!("plan-{suffix}")));
    body.insert("name".to_owned(), Value::String(format!("Plan {suffix}")));
    body.insert("description".to_owned(), Value::Null);
    body.insert("is_default".to_owned(), Value::Bool(false));
    body.extend(limits);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/plans")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(Value::Object(body).to_string()))
                .expect("create plan request"),
        )
        .await
        .expect("create plan response");
    assert_eq!(response.status(), StatusCode::CREATED, "create plan");
    json(response).await
}

/// 常用限额组合，省掉每个测试重复构造 `serde_json::Map`。
pub fn plan_limits(
    oauth_clients_limit: i64,
    daily_auth_limit: i64,
    monthly_auth_limit: Option<i64>,
    max_qps: Option<i64>,
) -> serde_json::Map<String, Value> {
    let mut limits = serde_json::Map::new();
    limits.insert(
        "oauth_clients_limit".to_owned(),
        Value::from(oauth_clients_limit),
    );
    limits.insert("daily_auth_limit".to_owned(), Value::from(daily_auth_limit));
    limits.insert(
        "monthly_auth_limit".to_owned(),
        monthly_auth_limit.map_or(Value::Null, Value::from),
    );
    limits.insert(
        "max_qps".to_owned(),
        max_qps.map_or(Value::Null, Value::from),
    );
    limits
}

pub async fn update_plan(
    router: &Router,
    plan_id: i64,
    code: &str,
    is_default: bool,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/plans/{plan_id}"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "code": code,
                        "name": "Updated plan",
                        "description": null,
                        "oauth_clients_limit": 2,
                        "daily_auth_limit": 2500,
                        "monthly_auth_limit": 50000,
                        "max_qps": null,
                        "is_default": is_default,
                    })
                    .to_string(),
                ))
                .expect("update plan request"),
        )
        .await
        .expect("update plan response");
    let status = response.status();
    (status, json(response).await)
}

pub async fn archive_plan(router: &Router, plan_id: i64) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/plans/{plan_id}/archive"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("archive request"),
        )
        .await
        .expect("archive response")
}

pub async fn restore_plan(router: &Router, plan_id: i64) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/plans/{plan_id}/restore"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("restore request"),
        )
        .await
        .expect("restore response")
}

pub async fn assign_plan(
    router: &Router,
    user_id: i64,
    plan_id: i64,
    expires_at: Option<Value>,
) -> StatusCode {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/plan"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "plan_id": plan_id, "expires_at": expires_at }).to_string(),
                ))
                .expect("assign plan request"),
        )
        .await
        .expect("assign plan response");
    response.status()
}

pub async fn list_plans(router: &Router) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/plans")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("list plans request"),
        )
        .await
        .expect("list plans response");
    assert_eq!(response.status(), StatusCode::OK, "list plans");
    json(response).await
}

pub async fn get_entitlements(router: &Router, cookie: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/entitlements")
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("entitlements request"),
        )
        .await
        .expect("entitlements response");
    let status = response.status();
    (status, json(response).await)
}

pub async fn list_owned_clients(router: &Router, cookie: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("owned client list request"),
        )
        .await
        .expect("owned client list response");
    let status = response.status();
    (status, json(response).await)
}

pub fn validated_request(client_id: &str, user_id: i64) -> ValidatedAuthorizationRequest {
    validated_request_with_challenge(client_id, user_id, "plan-challenge")
}

/// 需要真正兑换令牌的用例必须给出 S256 challenge —— Token 端点会校验
/// `code_verifier`，随手写的字符串过不了 PKCE。
pub fn validated_request_with_challenge(
    client_id: &str,
    user_id: i64,
    code_challenge: &str,
) -> ValidatedAuthorizationRequest {
    ValidatedAuthorizationRequest {
        client_id: client_id.to_owned(),
        redirect_uri: REDIRECT_URI.to_owned(),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        state: "plan-state".to_owned(),
        nonce: None,
        code_challenge: code_challenge.to_owned(),
        owner_user_id: Some(user_id),
        session_token_hash: None,
    }
}

/// PKCE `code_verifier` → S256 `code_challenge`。
pub fn code_challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// 从 authorize 重定向 URL 中取出授权码。
pub fn authorization_code_from_redirect(redirect: &str) -> String {
    url::Url::parse(redirect)
        .expect("authorization redirect URL")
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .expect("authorization code in redirect")
}

/// 用 client_secret_basic 兑换授权码。
pub async fn exchange_authorization_code(
    router: &Router,
    client_id: &str,
    client_secret: &str,
    code: &str,
    verifier: &str,
) -> (StatusCode, Value) {
    let credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("code_verifier", verifier)
        .finish();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("token request"),
        )
        .await
        .expect("token response");
    let status = response.status();
    (status, json(response).await)
}
