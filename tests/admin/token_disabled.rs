use std::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::sessions::{cookies, domain::Session, store::SessionStore};
use tower::ServiceExt;

use crate::http;

async fn setup() -> (
    Router,
    chenxing_auth::sqlx::PgPool,
    String,
    std::path::PathBuf,
) {
    let harness = crate::harness::HarnessBuilder::new("admin_token_disabled")
        .admin_token("")
        .build()
        .await;
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    (
        harness.router,
        harness.database,
        redis_url,
        harness.key_directory,
    )
}

async fn assert_admin_disabled(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = http::json_body(response).await;
    assert_eq!(body["code"], "admin_disabled");
}

async fn browser_session(
    database: &chenxing_auth::sqlx::PgPool,
    redis_url: &str,
    user_id: i64,
) -> (String, String, String) {
    let redis = redis::Client::open(redis_url).expect("session Redis");
    let store = SessionStore::with_metadata_and_key(redis, database.clone(), [0; 32]);
    let mut session =
        Session::new(user_id.to_string(), Duration::from_secs(3600)).expect("browser session");
    store
        .save(&mut session, Duration::from_secs(3600))
        .await
        .expect("save browser session");
    let cookie = format!(
        "{}={}; {}={}",
        cookies::session_cookie_name(false),
        session.token,
        cookies::csrf_cookie_name(false),
        session.csrf_token
    );
    (cookie, session.csrf_token, session.token)
}

#[tokio::test]
async fn empty_admin_token_closes_bearer_and_browser_admin_channels_but_keeps_bootstrap() {
    let (router, database, redis_url, key_directory) = setup().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": "disabled-admin-token-owner",
                        "email": "disabled-admin-token-owner@example.com",
                        "password": "correct horse battery"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let owner_id = http::json_body(response).await["id"]
        .as_i64()
        .expect("bootstrapped owner id");

    let (owner_cookies, owner_csrf, owner_token) =
        browser_session(&database, &redis_url, owner_id).await;

    for uri in ["/api/v1/admin/auth/me", "/api/v1/admin/overview"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("cookie", &owner_cookies)
                    .body(Body::empty())
                    .expect("browser admin read request"),
            )
            .await
            .expect("browser admin read response");
        assert_admin_disabled(response).await;
    }

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/issuer")
                .header("cookie", &owner_cookies)
                .header("x-csrf-token", &owner_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "value": "https://auth.example.com",
                        "expected_generation": 0,
                        "confirm": false
                    })
                    .to_string(),
                ))
                .expect("browser admin write request"),
        )
        .await
        .expect("browser admin write response");
    assert_admin_disabled(response).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/overview")
                .header("authorization", "Bearer configured-looking-token")
                .body(Body::empty())
                .expect("Bearer admin request"),
        )
        .await
        .expect("Bearer admin response");
    assert_admin_disabled(response).await;

    let store = SessionStore::with_metadata_and_key(
        redis::Client::open(redis_url).expect("cleanup Redis"),
        database,
        [0; 32],
    );
    store
        .revoke(&owner_token)
        .await
        .expect("cleanup browser session");
    let _ = std::fs::remove_dir_all(key_directory);
}
