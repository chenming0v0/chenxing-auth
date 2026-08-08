use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use chenxing_auth::{api, config::Config, state::AppState};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

async fn test_router() -> (Router, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("api", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-api-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.cookie_secure = false;
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

#[tokio::test]
async fn liveness_endpoint_reports_process_status_without_dependencies() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn liveness_endpoint_includes_security_headers_without_hsts_for_http_issuer() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.headers()["x-frame-options"], "DENY");
    assert_eq!(
        response.headers()["content-security-policy"],
        "frame-ancestors 'none'"
    );
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert!(
        response
            .headers()
            .get("strict-transport-security")
            .is_none()
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn readiness_endpoint_returns_a_dependency_agnostic_failure_body() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert!(matches!(
        response.status(),
        StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
    ));
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("readiness body");
    let body = String::from_utf8(body.to_vec()).expect("UTF-8 readiness body");
    assert!(!body.contains("postgres"));
    assert!(!body.contains("redis://"));
    assert!(!body.contains("127.0.0.1"));
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn authorized_apps_endpoint_requires_a_session() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/authorized-apps")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn openid_configuration_publishes_standard_endpoints() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let configuration: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(
        configuration["revocation_endpoint"],
        "http://127.0.0.1:3000/oauth/revoke"
    );
    assert_eq!(
        configuration["token_endpoint_auth_methods_supported"],
        serde_json::json!(["client_secret_basic", "client_secret_post", "none"])
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn openid_configuration_allows_newapi_origin() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header("origin", "https://zd.chenl.ing")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("*")
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn jwks_endpoint_returns_a_key_set_document() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn registration_endpoint_rejects_invalid_email_without_database_call() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"invalid-user","email":"invalid","password":"correct horse battery","display_name":null}"#,
                ))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let _ = std::fs::remove_dir_all(key_directory);
}

/// POST 到管理侧用户创建端点必须落到处理器上。
///
/// 404/405 会说明路由没注册或只挂了 GET；401 才说明请求进了守卫（Issue #133）。
#[tokio::test]
async fn admin_user_creation_endpoint_rejects_unauthenticated_requests() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"newcomer","email":"newcomer@example.com","password":"correct horse battery"}"#,
                ))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 未认证请求在解析请求体前由 AdminWrite 拒绝，不应进入管理侧业务校验。
#[tokio::test]
async fn admin_user_creation_requires_admin_before_parsing_input() {
    let (router, key_directory) = test_router().await;
    for body in [
        r#"{"username":"newcomer","email":"newcomer@example.com","password":"correct horse battery","role":"superuser"}"#,
        r#"{"username":"newcomer","email":"newcomer@example.com","password":"correct horse battery","status":"deleted"}"#,
        // 大小写变体同样不在词表内，避免 handler 悄悄接受 "ACTIVE"。
        r#"{"username":"newcomer","email":"newcomer@example.com","password":"correct horse battery","status":"ACTIVE"}"#,
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("valid request"),
            )
            .await
            .expect("response from router");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
        assert_eq!(error["code"], "login_required");
    }
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn login_endpoint_rejects_invalid_identifier_without_database_call() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"identifier":"ab","password":"password"}"#))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
    assert_eq!(error["code"], "invalid_credentials");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn unknown_api_wellknown_and_health_paths_return_json_not_found_instead_of_spa_html() {
    let (router, key_directory) = test_router().await;
    for path in [
        "/api/v1/does-not-exist",
        "/.well-known/does-not-exist",
        "/health/does-not-exist",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("response from router");

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.split(';').next().unwrap_or(value)),
            Some("application/json"),
            "{path} content type"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
        assert_eq!(error["code"], "not_found", "{path} error code");
    }
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn unknown_static_asset_path_returns_not_found() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/assets/does-not-exist.js")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn unknown_frontend_route_returns_spa_html() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/some-frontend-route")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    let _ = std::fs::remove_dir_all(key_directory);
}
