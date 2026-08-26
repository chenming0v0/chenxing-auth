//! Issue #444 / #488：OpenAPI 契约必须与当前 HTTP 行为和发布结果一致。
//!
//! 静态断言钉住路径、`$ref` 和文档中的 Location；运行时断言钉住保护模式
//! readiness、本地登录可达性、Issuer 门禁信封、用户创建禁用和遗留管理页重定向。

use crate::db_isolation;
use crate::key_directory;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, LOCATION},
    },
};
use chenxing_auth::{
    api,
    audit::{
        SecurityEventCategory, SecurityEventClient, SecurityEventDetail, SecurityEventSeverity,
    },
    config::Config,
    state::AppState,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use time::OffsetDateTime;
use tower::ServiceExt;

const CI_WORKFLOW: &str = include_str!("../../.github/workflows/ci.yml");
const OPENAPI: &str = include_str!("../../openapi.yaml");
const ROUTE_SOURCES: &str = concat!(
    include_str!("../../src/api/routes.rs"),
    include_str!("../../src/api/mod.rs")
);

fn static_route_paths(source: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let mut pending = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if pending {
            if let Some(path) = quoted_path(trimmed) {
                paths.insert(path.to_owned());
                pending = false;
            } else if !trimmed.is_empty() && !trimmed.starts_with("//") {
                pending = false;
            }
        }
        if let Some(index) = line.find(".route(") {
            let rest = &line[index + ".route(".len()..];
            if let Some(path) = quoted_path(rest) {
                paths.insert(path.to_owned());
            } else {
                pending = true;
            }
        }
    }
    paths
}

fn quoted_path(value: &str) -> Option<&str> {
    let value = value.trim_start();
    let value = value.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(&value[..end])
}

fn openapi_paths() -> BTreeSet<String> {
    OPENAPI
        .lines()
        .filter_map(|line| {
            let value = line.strip_prefix("  /")?;
            let end = value.strip_suffix(':')?;
            Some(format!("/{end}"))
        })
        .collect()
}

fn openapi_section(start: &str, end: &str) -> String {
    let normalized = OPENAPI.replace("\r\n", "\n");
    let (_, section) = normalized
        .split_once(start)
        .unwrap_or_else(|| panic!("missing OpenAPI section start: {start}"));
    section
        .split_once(end)
        .map(|(section, _)| section.to_owned())
        .unwrap_or_else(|| panic!("missing OpenAPI section end: {end}"))
}

fn openapi_operation(path: &str, method: &str) -> String {
    let normalized = OPENAPI.replace("\r\n", "\n");
    let path_marker = format!("  {path}:\n");
    let (_, path_and_after) = normalized
        .split_once(&path_marker)
        .unwrap_or_else(|| panic!("missing OpenAPI path: {path}"));
    let path_section = path_and_after
        .split_once("\n  /")
        .map_or(path_and_after, |(section, _)| section);
    let method_marker = format!("    {method}:\n");
    let (_, operation_and_after) = path_section
        .split_once(&method_marker)
        .unwrap_or_else(|| panic!("missing OpenAPI operation: {method} {path}"));
    let end = operation_and_after
        .match_indices("\n    ")
        .find_map(|(offset, _)| {
            let line = operation_and_after[offset + 1..].lines().next()?;
            matches!(
                line,
                "    get:" | "    post:" | "    put:" | "    patch:" | "    delete:"
            )
            .then_some(offset)
        })
        .unwrap_or(operation_and_after.len());
    operation_and_after[..end].to_owned()
}

fn assert_openapi_response(operation: &str, status: &str, method: &str, path: &str) {
    assert!(
        operation.contains(&format!("        '{status}':")),
        "{method} {path} must declare runtime response {status}"
    );
}

fn security_event_detail(client: Option<SecurityEventClient>) -> SecurityEventDetail {
    SecurityEventDetail {
        id: 488,
        action: "oauth_consent".to_owned(),
        category: SecurityEventCategory::Authorization,
        severity: SecurityEventSeverity::Notice,
        resource_type: "oauth_client".to_owned(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        ip: None,
        ip_location: None,
        user_agent: None,
        ray_id: None,
        client,
    }
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
    state.worker_health.assume_ready_for_test();
    (state, database, key_directory)
}

#[test]
fn security_event_detail_serializes_required_null_client() {
    let value = serde_json::to_value(security_event_detail(None)).expect("serialize detail");
    let object = value.as_object().expect("detail object");
    let client = object.get("client").expect("client must remain required");

    assert!(client.is_null(), "client must serialize as null");
}

#[test]
fn security_event_detail_serializes_non_null_client_summary() {
    let value = serde_json::to_value(security_event_detail(Some(SecurityEventClient {
        client_id: "cx_contract".to_owned(),
        client_name: "Contract Client".to_owned(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        status: "active".to_owned(),
    })))
    .expect("serialize detail");

    assert_eq!(
        value["client"],
        json!({
            "client_id": "cx_contract",
            "client_name": "Contract Client",
            "created_at": "1970-01-01T00:00:00Z",
            "status": "active",
        })
    );
}

#[test]
fn openapi_declares_security_event_client_as_required_but_nullable() {
    let schema = openapi_section("    SecurityEventDetail:\n", "    SecurityEventClient:\n");

    assert!(
        schema.contains(
            "required: [id, action, category, severity, resource_type, created_at, ip, ip_location, user_agent, ray_id, client]"
        ),
        "SecurityEventDetail.client must remain required"
    );
    assert!(
        schema.contains(
            "        client:\n          allOf:\n            - $ref: '#/components/schemas/SecurityEventClient'\n          nullable: true"
        ),
        "SecurityEventDetail.client must remain a nullable SecurityEventClient reference"
    );
}

#[test]
fn apifox_import_removes_resources_absent_from_openapi() {
    assert!(
        CI_WORKFLOW.contains(r#""deleteUnmatchedResources": true"#),
        "Apifox import must delete endpoints and schemas removed from openapi.yaml"
    );
    assert!(
        !CI_WORKFLOW.contains(r#""deleteUnmatchedResources": false"#),
        "Apifox import must not preserve stale resources"
    );
}

#[test]
fn openapi_declares_health_probes_admin_login_and_valid_error_refs() {
    let openapi = OPENAPI.replace("\r\n", "\n");
    for path in [
        "  /health:",
        "  /health/live:",
        "  /health/ready:",
        "  /admin/login:",
        "  /admin/settings/oauth:",
    ] {
        assert!(openapi.contains(path), "missing path {path}");
    }
    assert!(
        openapi.contains("  /oauth/authorize:\n    get:")
            && openapi.contains(
                "    post:\n      tags: [OAuth/OIDC]\n      summary: OAuth 授权码入口（表单 POST）"
            )
    );
    assert!(openapi.contains("  /oauth/userinfo:\n    get:") && openapi.contains("    post:\n      tags: [OAuth/OIDC]\n      summary: 获取 OIDC UserInfo（表单 POST）"));
    for operation_id in [
        "operationId: healthLive",
        "operationId: healthReady",
        "operationId: adminLoginPage",
        "operationId: oauthProviderSettingsPage",
    ] {
        assert!(openapi.contains(operation_id), "missing {operation_id}");
    }
    assert!(
        !openapi.contains("#/components/responses/InternalError"),
        "broken InternalError $ref must not remain"
    );
    assert!(
        openapi.contains("#/components/responses/InternalServerError"),
        "issuer settings 500 must use InternalServerError"
    );
    assert!(
        openapi.contains("#/components/responses/HealthServiceUnavailable"),
        "ready probes must declare the 503 health schema"
    );
    for marker in ["PostgreSQL `app_settings`", "用户 ID=1", "ADMIN_TOKEN"] {
        assert!(
            openapi.contains(marker),
            "missing protection-mode marker: {marker}"
        );
    }
    for response in ["'413':", "'415':", "'422':"] {
        assert!(openapi.contains(response), "login must declare {response}");
    }
    assert_eq!(
        openapi
            .matches("#/components/responses/PayloadTooLarge")
            .count(),
        43,
        "every JSON request-body operation must declare the unified 413 envelope"
    );
    assert_eq!(
        openapi
            .matches("#/components/responses/UnsupportedMediaType")
            .count(),
        43,
        "every JSON request-body operation must declare the unified 415 envelope"
    );
    assert_eq!(
        openapi
            .matches("#/components/responses/InvalidJsonData")
            .count(),
        43,
        "every JSON request-body operation must declare the unified 422 envelope"
    );
    assert_eq!(
        openapi
            .matches("#/components/responses/InvalidPagination")
            .count(),
        4,
        "every pagination operation must declare invalid_pagination"
    );
    assert!(!openapi.contains("issuer_pending"));
    assert!(!openapi.contains("issuer_runtime_pending"));

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
fn openapi_documents_oauth_body_credential_alternatives() {
    let revoke = openapi_operation("/oauth/revoke", "post");
    assert!(revoke.contains("security: [{ basicClientAuth: [] }, {}]"));
    assert!(revoke.contains("$ref: '#/components/schemas/RevocationRequest'"));

    let revocation_schema =
        openapi_section("    RevocationRequest:\n", "    UserInfoPostRequest:\n");
    assert!(revocation_schema.contains("required: [token]"));
    assert!(revocation_schema.contains("client_id:"));
    assert!(revocation_schema.contains("client_secret:"));
    assert!(revocation_schema.contains("client_secret_post"));
    assert!(revocation_schema.contains("公开 Client 的 `none`"));

    let userinfo = openapi_operation("/oauth/userinfo", "post");
    assert!(userinfo.contains("security: [{ bearerAuth: [] }, {}]"));
    assert!(userinfo.contains("requestBody:\n        required: false"));
    assert!(userinfo.contains("$ref: '#/components/schemas/UserInfoPostRequest'"));

    let userinfo_schema = openapi_section("    UserInfoPostRequest:\n", "    TokenResponse:\n");
    assert!(userinfo_schema.contains("required: [access_token]"));
    assert!(userinfo_schema.contains("access_token:"));
    assert!(userinfo_schema.contains("Bearer"));
    assert!(userinfo_schema.contains("二选一"));
}

#[test]
fn openapi_models_admin_bearer_or_session_csrf_and_runtime_errors() {
    let read_operations = [
        ("get", "/api/v1/admin/auth/me"),
        ("get", "/api/v1/admin/users"),
        ("get", "/api/v1/admin/users/{user_id}/auth-factors"),
        ("get", "/api/v1/admin/auth-factors/key-health"),
        ("get", "/api/v1/admin/plans"),
        ("get", "/api/v1/admin/clients"),
        ("get", "/api/v1/admin/admins"),
        ("get", "/api/v1/admin/audit"),
        ("get", "/api/v1/admin/overview"),
        ("get", "/api/v1/admin/users/query"),
        ("get", "/api/v1/admin/clients/query"),
        ("get", "/api/v1/admin/audit/query"),
        ("get", "/api/v1/admin/settings/registration-email"),
        ("get", "/api/v1/admin/settings/issuer"),
        ("get", "/api/v1/admin/settings/passkey"),
        ("get", "/api/v1/admin/settings/email-policy"),
        ("get", "/api/v1/admin/settings/smtp"),
        ("get", "/api/v1/admin/settings/security-limits"),
        ("get", "/api/v1/admin/oauth/providers"),
    ];
    let write_operations = [
        ("post", "/api/v1/admin/users"),
        ("post", "/api/v1/admin/users/{user_id}/{status}"),
        ("post", "/api/v1/admin/users/{user_id}/role"),
        ("delete", "/api/v1/admin/users/{user_id}/auth-factors/totp"),
        (
            "delete",
            "/api/v1/admin/users/{user_id}/auth-factors/passkey",
        ),
        ("post", "/api/v1/admin/users/{user_id}/plan"),
        ("post", "/api/v1/admin/users/{user_id}/wallet/credit"),
        ("post", "/api/v1/admin/plans"),
        ("put", "/api/v1/admin/plans/{id}"),
        ("post", "/api/v1/admin/plans/{id}/archive"),
        ("post", "/api/v1/admin/plans/{id}/restore"),
        ("post", "/api/v1/admin/clients"),
        ("put", "/api/v1/admin/clients/{client_id}"),
        ("post", "/api/v1/admin/clients/{client_id}/disable"),
        ("post", "/api/v1/admin/clients/{client_id}/enable"),
        ("post", "/api/v1/admin/clients/{client_id}/rotate-secret"),
        ("post", "/api/v1/admin/admins"),
        ("put", "/api/v1/admin/settings/registration-email"),
        ("put", "/api/v1/admin/settings/issuer"),
        ("put", "/api/v1/admin/settings/passkey"),
        ("put", "/api/v1/admin/settings/email-policy"),
        ("put", "/api/v1/admin/settings/smtp"),
        ("put", "/api/v1/admin/settings/security-limits"),
        ("post", "/api/v1/admin/oauth/providers"),
        ("put", "/api/v1/admin/oauth/providers/{slug}"),
        ("post", "/api/v1/admin/oauth/providers/{slug}/disable"),
        ("post", "/api/v1/admin/oauth/providers/{slug}/enable"),
        ("post", "/api/v1/admin/keys/rotate"),
        ("post", "/api/v1/admin/keys/{key_id}/revoke"),
    ];
    let read_security = "security:\n        - adminBearer: []\n        - sessionCookie: []";
    let write_security = "security:\n        - adminBearer: []\n        - sessionCookie: []\n          csrfCookie: []\n          csrfHeader: []";

    for (method, path) in read_operations {
        let operation = openapi_operation(path, method);
        assert!(
            operation.contains(read_security),
            "{method} {path} must allow admin Bearer OR browser Session"
        );
        for status in ["401", "403"] {
            assert_openapi_response(&operation, status, method, path);
        }
        if path != "/api/v1/admin/settings/issuer" {
            assert_openapi_response(&operation, "503", method, path);
        }
    }

    for (method, path) in write_operations {
        let operation = openapi_operation(path, method);
        assert!(
            operation.contains(write_security),
            "{method} {path} must allow admin Bearer OR Session plus CSRF"
        );
        assert!(
            !operation.contains("#/components/parameters/CsrfHeader"),
            "{method} {path} must not require CSRF on the Bearer branch"
        );
        for status in ["400", "401", "403"] {
            assert_openapi_response(&operation, status, method, path);
        }
        if path != "/api/v1/admin/settings/issuer" {
            assert_openapi_response(&operation, "503", method, path);
        }
    }

    assert!(OPENAPI.contains("csrfHeader: { type: apiKey, in: header, name: X-CSRF-Token"));
    assert!(OPENAPI.contains("csrfCookie: { type: apiKey, in: cookie, name: __Host-chenxing_csrf"));
}

#[test]
fn totp_setup_operations_declare_the_issuer_gate() {
    for path in [
        "/api/v1/auth/totp/setup",
        "/api/v1/auth/security/totp/enrollment/start",
    ] {
        let operation = openapi_operation(path, "post");
        assert!(operation.contains("Issuer"), "{path}");
        assert_openapi_response(&operation, "503", "post", path);
    }
}

#[test]
fn openapi_paths_match_all_static_axum_routes() {
    let routes = static_route_paths(ROUTE_SOURCES);
    let paths = openapi_paths();
    assert_eq!(
        routes.len(),
        101,
        "route inventory changed; review contract"
    );
    assert_eq!(
        paths.len(),
        101,
        "OpenAPI path inventory changed; review contract"
    );
    assert_eq!(routes, paths, "Axum and OpenAPI path inventories diverged");
    assert!(
        ROUTE_SOURCES.contains(".route(\"/oauth/authorize\", get(authorize).post(authorize_post))")
    );
    assert!(
        ROUTE_SOURCES.contains(".route(\"/oauth/userinfo\", get(userinfo).post(userinfo_post))")
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
async fn discovery_auth_methods_match_token_and_revocation_contracts() {
    let (router, key_directory) = configured_issuer_router().await;
    let response = send(&router, Method::GET, "/.well-known/openid-configuration").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let expected = serde_json::json!(["client_secret_basic", "client_secret_post", "none"]);
    assert_eq!(body["token_endpoint_auth_methods_supported"], expected);
    assert_eq!(body["revocation_endpoint_auth_methods_supported"], expected);
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
        (Method::POST, "/oauth/userinfo"),
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

    for (method, path) in [
        (Method::GET, "/.well-known/openid-configuration"),
        (Method::GET, "/.well-known/jwks.json"),
        (
            Method::GET,
            "/api/v1/oauth/authorize/requests/contract-request",
        ),
        (Method::GET, "/api/v1/admin/oauth/providers"),
        (Method::GET, "/api/v1/auth/external-providers"),
        (Method::GET, "/auth/external/example"),
        (
            Method::GET,
            "/auth/external/example/callback?state=contract-state",
        ),
        (Method::POST, "/api/v1/auth/totp/setup"),
        (Method::POST, "/api/v1/auth/security/totp/enrollment/start"),
    ] {
        let response = send(&router, method, path).await;
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
    let bootstrap_id = json_body(bootstrap).await["id"]
        .as_i64()
        .expect("bootstrap response must contain a numeric id");
    assert!(
        bootstrap_id > 0,
        "bootstrap response id must be positive, got {bootstrap_id}"
    );

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
