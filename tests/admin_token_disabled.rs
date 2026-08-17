use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    config::Config,
    sessions::{cookies, domain::Session, store::SessionStore},
    state::AppState,
};
use serde_json::Value;
use tower::ServiceExt;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

async fn setup() -> (
    Router,
    chenxing_auth::sqlx::PgPool,
    String,
    std::path::PathBuf,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("admin_token_disabled", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("admin-token-disabled");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url.clone(),
        3600,
    )
    .expect("config");
    config.admin_token.clear();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("state");

    (api::router(state), database, redis_url, key_directory)
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("JSON")
}

async fn assert_admin_disabled(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = json(response).await;
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
    let owner_id = json(response).await["id"]
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
