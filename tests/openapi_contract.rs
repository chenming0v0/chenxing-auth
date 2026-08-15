//! Issue #444：OpenAPI 契约必须与当前 HTTP 行为一致。
//!
//! 静态断言钉住路径、`$ref` 和文档中的 Location；运行时断言钉住保护模式
//! readiness、本地登录可达性、Issuer 门禁信封、用户创建禁用和遗留管理页重定向。

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, LOCATION},
    },
};
use chenxing_auth::{api, config::Config, state::AppState};
use serde_json::Value;
use tower::ServiceExt;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

const OPENAPI: &str = include_str!("../openapi.yaml");

fn openapi_section(start: &str, end: &str) -> &'static str {
    let (_, section) = OPENAPI
        .split_once(start)
        .unwrap_or_else(|| panic!("missing OpenAPI section start: {start}"));
    section
        .split_once(end)
        .map(|(section, _)| section)
        .unwrap_or_else(|| panic!("missing OpenAPI section end: {end}"))
}

fn json_content_type(response: &axum::response::Response) -> Option<&str> {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON body")
}

async fn send(router: &Router, method: Method, uri: &str) -> axum::response::Response {
    send_request(router, method, uri, None, None, Body::empty()).await
}

async fn send_request(
    router: &Router,
    method: Method,
    uri: &str,
    content_type: Option<&str>,
    authorization: Option<&str>,
    body: Body,
) -> axum::response::Response {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(content_type) = content_type {
        request = request.header(CONTENT_TYPE, content_type);
    }
    if let Some(authorization) = authorization {
        request = request.header(AUTHORIZATION, authorization);
    }
    router
        .clone()
        .oneshot(request.body(body).expect("valid request"))
        .await
        .expect("response from router")
}

async fn missing_issuer_router() -> (Router, std::path::PathBuf) {
    let (state, _database, key_directory) = contract_state(None).await;
    (api::router(state), key_directory)
}

async fn configured_issuer_router() -> (Router, std::path::PathBuf) {
    let (state, _database, key_directory) = contract_state(Some("http://127.0.0.1:3000")).await;
    (api::router(state), key_directory)
}

async fn contract_state(
    issuer: Option<&str>,
) -> (AppState, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("openapi_contract", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("openapi-contract");
    let mut config = match issuer {
        Some(issuer) => Config::from_values_with_issuer(
            "127.0.0.1".to_owned(),
            3000,
            issuer.to_owned(),
            database_url,
            redis_url,
            3600,
        ),
        None => Config::from_values("127.0.0.1".to_owned(), 3000, database_url, redis_url, 3600),
    }
    .expect("config");
    if issuer.is_none() {
        config.issuer = None;
    }
    config.cookie_secure = false;
    config.admin_token = "openapi-contract-admin".to_owned();
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("state");
    (state, database, key_directory)
}

#[test]
fn openapi_declares_health_probes_admin_login_and_valid_error_refs() {
    for path in [
        "  /health:",
        "  /health/live:",
        "  /health/ready:",
        "  /admin/login:",
        "  /admin/settings/oauth:",
    ] {
        assert!(OPENAPI.contains(path), "missing path {path}");
    }
    for operation_id in [
        "operationId: healthLive",
        "operationId: healthReady",
        "operationId: adminLoginPage",
        "operationId: oauthProviderSettingsPage",
    ] {
        assert!(OPENAPI.contains(operation_id), "missing {operation_id}");
    }
    assert!(
        !OPENAPI.contains("#/components/responses/InternalError"),
        "broken InternalError $ref must not remain"
    );
    assert!(
        OPENAPI.contains("#/components/responses/InternalServerError"),
        "issuer settings 500 must use InternalServerError"
    );
    assert!(
        OPENAPI.contains("#/components/responses/HealthServiceUnavailable"),
        "ready probes must declare the 503 health schema"
    );
    for marker in ["PostgreSQL `app_settings`", "用户 ID=1", "ADMIN_TOKEN"] {
        assert!(
            OPENAPI.contains(marker),
            "missing protection-mode marker: {marker}"
        );
    }
    for response in ["'415':", "'422':"] {
        assert!(OPENAPI.contains(response), "login must declare {response}");
    }
    assert!(!OPENAPI.contains("issuer_pending"));
    assert!(!OPENAPI.contains("issuer_runtime_pending"));

    let login = openapi_section("  /api/v1/auth/login:\n", "  /api/v1/auth/totp/setup:\n");
    assert!(login.contains("请求先经过 Issuer 门禁"));
    assert!(login.contains("合法持久化 Issuer 会应用到当前请求并继续"));
    assert!(login.contains("数据库确实无记录时进入保护模式"));
    assert!(login.contains("issuer_runtime_invalid"));
    assert!(login.contains("415 或 422"));

    let discovery = openapi_section(
        "  /.well-known/openid-configuration:\n",
        "  /.well-known/jwks.json:\n",
    );
    assert!(discovery.contains("Runtime 处于 AwaitingIssuer"));
    assert!(discovery.contains("应用到当前请求"));
}

#[test]
fn openapi_documents_legacy_admin_redirect_targets() {
    assert!(
        OPENAPI.contains("example: /admin/settings"),
        "OAuth settings page must document Location /admin/settings"
    );
    assert!(
        OPENAPI.contains("example: /login"),
        "admin login page must document Location /login"
    );
    assert!(
        !OPENAPI.contains("/console/settings"),
        "OAuth settings page must not document the retired /console/settings target"
    );
}

#[tokio::test]
async fn readiness_probes_return_200_when_issuer_is_missing() {
    let (router, key_directory) = missing_issuer_router().await;

    for path in ["/health", "/health/live", "/health/ready"] {
        let response = send(&router, Method::GET, path).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            json_content_type(&response),
            Some("application/json"),
            "{path}"
        );
        let body = json_body(response).await;
        assert_eq!(body["status"], "ok", "{path}");
        assert_eq!(body["service"], "chenxing-auth", "{path}");
        assert!(body.get("error").is_none(), "{path}");
        assert!(body.get("code").is_none(), "{path}");
    }

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn readiness_probes_return_503_when_database_and_runtime_issuer_diverge() {
    let (state, database, key_directory) = contract_state(Some("http://127.0.0.1:3000")).await;
    assert!(
        chenxing_auth::settings::issuer::load(&database)
            .await
            .expect("load absent issuer")
            .is_none()
    );
    let router = api::router(state);
    for path in ["/health", "/health/ready"] {
        let response = send(&router, Method::GET, path).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(json_body(response).await["status"], "unavailable", "{path}");
    }
    let _ = std::fs::remove_dir_all(key_directory);

    let (state, database, key_directory) = contract_state(None).await;
    chenxing_auth::settings::issuer::initialize(&database, "http://127.0.0.1:3000")
        .await
        .expect("persist issuer without loading runtime");
    let router = api::router(state);
    for path in ["/health", "/health/ready"] {
        let response = send(&router, Method::GET, path).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(json_body(response).await["status"], "unavailable", "{path}");
    }
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn awaiting_gate_applies_a_valid_persisted_issuer_to_the_current_request() {
    let (state, database, key_directory) = contract_state(None).await;
    chenxing_auth::settings::issuer::initialize(&database, "http://127.0.0.1:3000")
        .await
        .expect("persist issuer from another instance");
    let runtime = state.issuer.clone();
    assert!(!runtime.is_ready());
    let router = api::router(state);

    let response = send(&router, Method::GET, "/.well-known/openid-configuration").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["issuer"], "http://127.0.0.1:3000");
    assert!(runtime.is_ready());

    let readiness = send(&router, Method::GET, "/health/ready").await;
    assert_eq!(readiness.status(), StatusCode::OK);
    assert_eq!(json_body(readiness).await["status"], "ok");

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn missing_issuer_keeps_local_login_reachable_for_request_validation() {
    let (router, key_directory) = missing_issuer_router().await;

    let response = send(&router, Method::POST, "/api/v1/auth/login").await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let response = send_request(
        &router,
        Method::POST,
        "/api/v1/auth/login",
        Some("application/json"),
        None,
        Body::from("{}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn issuer_gate_preserves_protocol_and_internal_error_envelopes() {
    let (router, key_directory) = missing_issuer_router().await;

    for (method, path) in [
        (Method::GET, "/oauth/authorize"),
        (Method::POST, "/oauth/token"),
        (Method::POST, "/oauth/revoke"),
        (Method::GET, "/oauth/userinfo"),
    ] {
        let response = send(&router, method, path).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(
            json_content_type(&response),
            Some("application/json"),
            "{path}"
        );
        let body = json_body(response).await;
        assert_eq!(body["error"], "temporarily_unavailable", "{path}");
        assert!(body["error_description"].as_str().is_some(), "{path}");
        assert!(body.get("code").is_none(), "{path}");
        assert!(body.get("message").is_none(), "{path}");
    }

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/api/v1/oauth/authorize/requests/contract-request",
        "/api/v1/admin/oauth/providers",
        "/api/v1/auth/external-providers",
        "/auth/external/example",
        "/auth/external/example/callback?state=contract-state",
    ] {
        let response = send(&router, Method::GET, path).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(
            json_content_type(&response),
            Some("application/json"),
            "{path}"
        );
        let body = json_body(response).await;
        assert_eq!(body["code"], "issuer_not_configured", "{path}");
        assert!(body["message"].as_str().is_some(), "{path}");
        assert!(body.get("error").is_none(), "{path}");
    }

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn missing_issuer_disables_registration_and_all_non_bootstrap_user_creation() {
    let (router, key_directory) = missing_issuer_router().await;

    let bootstrap = send_request(
        &router,
        Method::POST,
        "/api/v1/admin/bootstrap",
        Some("application/json"),
        None,
        Body::from(
            r#"{"username":"contract-owner","email":"contract-owner@example.com","password":"contract-password"}"#,
        ),
    )
    .await;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);
    assert_eq!(json_body(bootstrap).await["id"], 1);

    for (path, body, authorization) in [
        (
            "/api/v1/users",
            r#"{"username":"contract-user","email":"contract-user@example.com","password":"contract-password"}"#,
            None,
        ),
        (
            "/api/v1/admin/users",
            r#"{"username":"managed-user","email":"managed-user@example.com","password":"contract-password","role":"user","status":"active"}"#,
            Some("Bearer openapi-contract-admin"),
        ),
        (
            "/api/v1/admin/admins",
            r#"{"username":"managed-admin","email":"managed-admin@example.com","password":"contract-password","role":"admin"}"#,
            Some("Bearer openapi-contract-admin"),
        ),
    ] {
        let response = send_request(
            &router,
            Method::POST,
            path,
            Some("application/json"),
            authorization,
            Body::from(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(
            json_content_type(&response),
            Some("application/json"),
            "{path}"
        );
        let body = json_body(response).await;
        assert_eq!(body["code"], "issuer_not_configured", "{path}");
        assert!(body.get("error").is_none(), "{path}");
    }

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn legacy_admin_pages_redirect_to_spa_routes() {
    let (router, key_directory) = configured_issuer_router().await;

    for (uri, expected) in [
        ("/admin/login", "/login"),
        (
            "/admin/login?returnTo=%2Fadmin%2Fusers",
            "/login?returnTo=%2Fadmin%2Fusers",
        ),
        ("/admin/settings/oauth", "/admin/settings"),
        (
            "/admin/settings/oauth?state=provider-state",
            "/admin/settings?state=provider-state",
        ),
    ] {
        let response = send(&router, Method::GET, uri).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{uri}");
        assert_eq!(response.headers()[LOCATION], expected, "{uri}");
    }

    let _ = std::fs::remove_dir_all(key_directory);
}
