//! Issue #444：OpenAPI 契约必须与当前 HTTP 行为一致。
//!
//! 静态断言钉住路径、`$ref` 和文档中的 Location；运行时断言钉住健康探针
//! 503、Issuer 门禁信封、以及遗留管理页重定向。

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
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
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router")
}

async fn missing_issuer_router() -> (Router, std::path::PathBuf) {
    contract_router(None).await
}

async fn configured_issuer_router() -> (Router, std::path::PathBuf) {
    contract_router(Some("http://127.0.0.1:3000")).await
}

async fn contract_router(issuer: Option<&str>) -> (Router, std::path::PathBuf) {
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
    (
        api::router(
            AppState::new_with_pool(config, database)
                .await
                .expect("state"),
        ),
        key_directory,
    )
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
async fn readiness_probes_return_503_when_issuer_is_missing() {
    let (router, key_directory) = missing_issuer_router().await;

    let live = send(&router, Method::GET, "/health/live").await;
    assert_eq!(live.status(), StatusCode::OK);
    assert_eq!(json_content_type(&live), Some("application/json"));
    let live_body = json_body(live).await;
    assert_eq!(live_body["status"], "ok");
    assert_eq!(live_body["service"], "chenxing-auth");

    for path in ["/health", "/health/ready"] {
        let response = send(&router, Method::GET, path).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(
            json_content_type(&response),
            Some("application/json"),
            "{path}"
        );
        let body = json_body(response).await;
        assert_eq!(body["status"], "unavailable", "{path}");
        assert_eq!(body["service"], "chenxing-auth", "{path}");
        assert!(body.get("error").is_none(), "{path}");
        assert!(body.get("code").is_none(), "{path}");
    }

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn issuer_gate_uses_oauth_envelope_only_on_protocol_endpoints() {
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

    let response = send(&router, Method::POST, "/api/v1/auth/login").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_content_type(&response), Some("application/json"));
    let body = json_body(response).await;
    assert_eq!(body["code"], "issuer_not_configured");
    assert!(body["message"].as_str().is_some());
    assert!(body.get("error").is_none());

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
