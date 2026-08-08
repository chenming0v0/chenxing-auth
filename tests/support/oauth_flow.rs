#![allow(dead_code)]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::SET_COOKIE},
};
use chenxing_auth::{api, config::Config, state::AppState};
use serde_json::Value;
use tower::ServiceExt;

#[path = "key_directory.rs"]
mod key_directory;

/// `binary_name` 决定 schema 隔离边界，必须传调用方测试二进制自己的名字
/// （见 `support/db_isolation.rs`）。共享同一个名字的二进制会共享数据库状态。
///
/// 调用方必须同时声明 `db_isolation` 模块：
/// ```rust,ignore
/// #[path = "support/db_isolation.rs"]
/// mod db_isolation;
/// #[path = "support/oauth_flow.rs"]
/// mod oauth_flow;
/// ```
pub async fn test_state(
    binary_name: &str,
) -> (AppState, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = crate::db_isolation::isolated_pool(binary_name, &database_url).await;
    let key_directory = key_directory::isolated_key_directory("flow");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.admin_token = "flow-admin-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state");
    (state, database, key_directory)
}

pub async fn test_router(
    binary_name: &str,
) -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let (state, database, key_directory) = test_state(binary_name).await;
    (api::router(state), database, key_directory)
}

pub async fn json_body(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

pub fn cookie_header(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().expect("cookie value"))
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn session_cookie(session: &chenxing_auth::sessions::domain::Session) -> String {
    format!(
        "chenxing_session={}; chenxing_csrf={}",
        session.token, session.csrf_token
    )
}

pub async fn register_test_user(router: &Router, suffix: &str) -> (i64, String, String, String) {
    let username = format!("disabled-{suffix}");
    let email = format!("disabled-{suffix}@example.com");
    let password = "correct horse battery";
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password,
                    })
                    .to_string(),
                ))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    let status = response.status();
    let body = json_body(response).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "registration response: {body}"
    );
    assert_eq!(body["code"], "email_verification_unavailable");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer flow-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password,
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    let status = response.status();
    let body = json_body(response).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "admin user creation response: {body}"
    );
    let user_id = body["id"].as_i64().expect("numeric user id");
    (user_id, username, email, password.to_owned())
}

pub async fn ensure_owner_bootstrapped(router: &Router, suffix: &str) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("test-owner-{suffix}"),
                        "email": format!("test-owner-{suffix}@example.com"),
                        "password": "correct horse battery",
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert!(
        matches!(
            response.status(),
            StatusCode::CREATED | StatusCode::CONFLICT
        ),
        "unexpected bootstrap response: {}",
        response.status()
    );
}

pub async fn create_test_client(router: &Router, token: &str) -> (String, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "Disabled User Client",
                        "redirect_uris": ["https://disabled.example/callback"],
                        "scopes": ["openid", "profile", "email"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let client = json_body(response).await;
    (
        client["client_id"].as_str().expect("client id").to_owned(),
        client["client_secret"]
            .as_str()
            .expect("client secret")
            .to_owned(),
    )
}

pub async fn disable_user(database: &chenxing_auth::sqlx::PgPool, user_id: i64) {
    chenxing_auth::sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
        .bind(user_id)
        .execute(database)
        .await
        .expect("disable user");
}
