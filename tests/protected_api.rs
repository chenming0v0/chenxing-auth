use axum::{
    Router,
    body::Body,
    http::{
        Method, Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    },
};
use chenxing_auth::config::Config;
use chenxing_auth::{api, state::AppState};
use serde_json::Value;
use std::fs;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

const TEST_ADMIN_TOKEN: &str = "test-admin-token-0123456789abcdef";

fn get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("valid GET request")
}

fn content_type(response: &axum::response::Response) -> Option<&str> {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
}

async fn test_router() -> (Router, std::path::PathBuf) {
    let key_directory = std::env::temp_dir().join(format!("chenxing-protected-{}", Uuid::new_v4()));
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("protected_api", &database_url).await;
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.cookie_secure = false;
    config.admin_token = TEST_ADMIN_TOKEN.to_owned();
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(
            AppState::new_with_pool(config, database)
                .await
                .expect("test state"),
        ),
        key_directory,
    )
}

async fn admin_router() -> (Router, String, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!("chenxing-admin-keys-{}", Uuid::new_v4()));
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("protected_api", &database_url).await;
    let mut config =
        Config::from_values("127.0.0.1".to_owned(), 3000, database_url, redis_url, 3600)
            .expect("test configuration");
    config.admin_token = TEST_ADMIN_TOKEN.to_owned();
    config.key_directory = directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database)
        .await
        .expect("test state");
    (api::router(state), TEST_ADMIN_TOKEN.to_owned(), directory)
}

#[tokio::test]
async fn userinfo_requires_bearer_token() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_routes_forward_to_the_react_spa() {
    let (router, key_directory) = test_router().await;
    for uri in [
        "/admin",
        "/admin?tab=overview",
        "/admin/users?search=alice&status=active&page=2",
        "/admin/clients?page=3",
        "/admin/audit?action=login&resource_type=user",
    ] {
        let response = router
            .clone()
            .oneshot(get_request(uri))
            .await
            .expect("admin page response");
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(content_type(&response), Some("text/html"), "{uri}");
        assert!(!response.headers().contains_key(LOCATION), "{uri}");
    }
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_login_post_is_rejected_with_405() {
    // POST /admin/login used to be a 303 redirect, which silently dropped the
    // form body and turned the request into a GET (issue #357). The legacy
    // form-login flow no longer exists, so POST must be rejected explicitly
    // instead of pretending to accept credentials.
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/admin/login?returnTo=%2Fadmin%2Fusers%3Fpage%3D2&state=login-state")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("admin login response");

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        !response.headers().contains_key(LOCATION),
        "{:?}",
        response.headers()
    );
    assert!(
        response.headers()[axum::http::header::ALLOW]
            .to_str()
            .is_ok_and(|allow| allow.contains("GET")),
        "405 must advertise the allowed methods"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_legacy_redirects_preserve_query_parameters() {
    let (router, key_directory) = test_router().await;
    for (uri, expected) in [
        ("/admin/login", "/login"),
        (
            "/admin/login?returnTo=%2Fadmin%2Fusers%3Fpage%3D2&state=login-state",
            "/login?returnTo=%2Fadmin%2Fusers%3Fpage%3D2&state=login-state",
        ),
        ("/admin/settings/oauth", "/admin/settings"),
        (
            "/admin/settings/oauth?state=provider-state",
            "/admin/settings?state=provider-state",
        ),
    ] {
        let response = router
            .clone()
            .oneshot(get_request(uri))
            .await
            .expect("admin page response");
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{uri}");
        assert_eq!(response.headers()[LOCATION], expected, "{uri}");
    }
    let _ = std::fs::remove_dir_all(key_directory);
}

#[test]
fn admin_paths_exist_in_react_app() {
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
    let (router, key_directory) = test_router().await;
    let response = router
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
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn signing_key_rotation_requires_admin_bearer_token() {
    let (router, key_directory) = test_router().await;
    let response = router
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
    let _ = std::fs::remove_dir_all(key_directory);
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
