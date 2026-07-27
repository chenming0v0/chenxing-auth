use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::{api, state::AppState};
use tower::ServiceExt;

fn test_router() -> Router {
    api::router(AppState::for_test())
}

#[tokio::test]
async fn health_endpoint_reports_service_status() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
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
                    r#"{"email":"invalid","password":"correct horse battery","display_name":null}"#,
                ))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_endpoint_rejects_invalid_email_without_database_call() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"email":"invalid","password":"password"}"#))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
