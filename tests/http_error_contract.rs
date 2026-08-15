use std::time::Duration;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    config::Config,
    sessions::{cookies, domain::Session, store::SessionStore},
    state::AppState,
};
use tower::ServiceExt;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

#[tokio::test]
async fn auth_status_propagates_user_lookup_failures() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("http_error_contract", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("http-error-contract");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url.clone(),
        3600,
    )
    .expect("config");
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();

    let mut state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("state");
    let sessions =
        SessionStore::with_redis_key(redis::Client::open(redis_url).expect("Redis URL"), [0; 32]);
    let mut session = Session::new("1".to_owned(), Duration::from_secs(60)).expect("session");
    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    state.sessions = sessions;

    database.close().await;
    let response = api::router(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/status")
                .header(
                    "cookie",
                    format!("{}={}", cookies::session_cookie_name(false), session.token),
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let body: serde_json::Value = serde_json::from_slice(&body).expect("error envelope");
    assert_eq!(body["code"], "internal_error");
    assert_eq!(body["message"], "internal server error");
    assert!(body.get("authenticated").is_none());

    let _ = std::fs::remove_dir_all(key_directory);
}
