use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use chenxing_auth::{api, state::AppState};
use tower::ServiceExt;

fn test_router() -> Router {
    api::router(AppState::for_test())
}

#[tokio::test]
async fn liveness_endpoint_reports_process_status_without_dependencies() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn readiness_endpoint_returns_a_dependency_agnostic_failure_body() {
    let response = test_router()
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
}

#[tokio::test]
async fn authorized_apps_endpoint_requires_a_session() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/authorized-apps")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn openid_configuration_publishes_standard_endpoints() {
    let response = test_router()
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
}

#[tokio::test]
async fn openid_configuration_allows_newapi_origin() {
    let response = test_router()
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
}

#[tokio::test]
async fn jwks_endpoint_returns_a_key_set_document() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn registration_endpoint_rejects_invalid_email_without_database_call() {
    let response = test_router()
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
}

#[tokio::test]
async fn login_endpoint_rejects_invalid_identifier_without_database_call() {
    let response = test_router()
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
}

#[tokio::test]
async fn unknown_protocol_paths_return_json_not_found_instead_of_spa_html() {
    for path in [
        "/api/v1/does-not-exist",
        "/.well-known/does-not-exist",
        "/oauth/does-not-exist",
        "/health/does-not-exist",
    ] {
        let response = test_router()
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
}

#[tokio::test]
async fn unknown_static_asset_path_returns_not_found() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/assets/does-not-exist.js")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_frontend_route_returns_spa_html() {
    let response = test_router()
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
}
