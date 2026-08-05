use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use chenxing_auth::config::Config;
use chenxing_auth::{api, state::AppState};
use serde_json::Value;
use std::fs;
use tower::ServiceExt;
use uuid::Uuid;

async fn test_router() -> Router {
    api::router(AppState::for_test().await)
}

async fn admin_router() -> (Router, String, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!("chenxing-admin-keys-{}", Uuid::new_v4()));
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let mut config =
        Config::from_values("127.0.0.1".to_owned(), 3000, database_url, redis_url, 3600)
            .expect("test configuration");
    config.admin_token = "admin-secret".to_owned();
    config.key_directory = directory.to_string_lossy().into_owned();
    let state = AppState::new(config).await.expect("test state");
    (api::router(state), "admin-secret".to_owned(), directory)
}

#[tokio::test]
async fn userinfo_requires_bearer_token() {
    let response = test_router()
        .await
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
    let router = test_router().await;
    for (uri, expected) in [
        ("/admin/login", "/login"),
        ("/admin", "/admin"),
        ("/admin/users", "/admin/users"),
        ("/admin/clients", "/admin/clients"),
        ("/admin/audit", "/admin/audit"),
        ("/admin/settings/oauth", "/admin/settings"),
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
async fn admin_login_post_redirects_to_react_login() {
    let response = test_router()
        .await
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/admin/login?returnTo=%2Fadmin%2Fusers%3Fpage%3D2&state=login-state")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("admin login response");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[axum::http::header::LOCATION],
        "/login?returnTo=%2Fadmin%2Fusers%3Fpage%3D2&state=login-state"
    );
}

#[tokio::test]
async fn admin_redirects_preserve_query_parameters() {
    let router = test_router().await;
    for (uri, expected) in [
        ("/admin?tab=overview", "/admin?tab=overview"),
        (
            "/admin/users?search=alice&status=active&page=2",
            "/admin/users?search=alice&status=active&page=2",
        ),
        ("/admin/clients?page=3", "/admin/clients?page=3"),
        (
            "/admin/audit?action=login&resource_type=user",
            "/admin/audit?action=login&resource_type=user",
        ),
        (
            "/admin/settings/oauth?state=provider-state",
            "/admin/settings?state=provider-state",
        ),
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

#[test]
fn admin_redirect_targets_exist_in_react_app() {
    let app = include_str!("../web/src/App.tsx");
    for target in [
        "/login",
        "/admin",
        "/admin/users",
        "/admin/clients",
        "/admin/audit",
        "/admin/settings",
    ] {
        assert!(
            app.contains(&format!("'{target}':")),
            "redirect target {target} must be declared in App.tsx"
        );
    }
}

#[tokio::test]
async fn client_management_requires_admin_bearer_token() {
    let response = test_router()
        .await
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
        .await
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
    let (router, admin_token, directory) = admin_router().await;
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
