use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::config::Config;
use chenxing_auth::{api, state::AppState};
use serde_json::Value;
use std::fs;
use tower::ServiceExt;
use uuid::Uuid;

fn test_router() -> Router {
    api::router(AppState::for_test())
}

fn admin_router() -> (Router, String, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!("chenxing-admin-keys-{}", Uuid::new_v4()));
    let mut config = Config::from_values(
        "127.0.0.1".to_owned(),
        3000,
        "postgres://localhost/chenxing_auth".to_owned(),
        "redis://localhost".to_owned(),
        3600,
    )
    .expect("test configuration");
    config.admin_token = "admin-secret".to_owned();
    config.key_directory = directory.to_string_lossy().into_owned();
    let state = AppState::new(config).expect("test state");
    (api::router(state), "admin-secret".to_owned(), directory)
}

#[tokio::test]
async fn userinfo_requires_bearer_token() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_routes_forward_to_the_react_spa() {
    let router = test_router();
    for (uri, expected) in [
        ("/admin/login", "/auth/login"),
        ("/admin", "/console"),
        ("/admin/users", "/console/users"),
        ("/admin/clients", "/console/developer"),
        ("/admin/audit", "/console/overview"),
        ("/admin/settings/oauth", "/console/settings"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("admin page response");
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{uri}");
        assert_eq!(
            response.headers()[axum::http::header::LOCATION],
            expected,
            "{uri}"
        );
    }
}

#[tokio::test]
async fn client_management_requires_admin_bearer_token() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"client_name":"项目","redirect_uris":["https://project.example/callback"],"scopes":["openid"]}"#,
                ))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signing_key_rotation_requires_admin_bearer_token() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/keys/rotate")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signing_key_rotation_returns_public_key_metadata_for_admin() {
    let (router, admin_token, directory) = admin_router();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/keys/rotate")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let payload: Value = serde_json::from_slice(&body).expect("JSON response");
    assert!(
        payload["key_id"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(
        payload["published_key_count"]
            .as_u64()
            .is_some_and(|value| value >= 2)
    );
    assert!(payload.get("private_key").is_none());

    let _ = fs::remove_dir_all(directory);
}
