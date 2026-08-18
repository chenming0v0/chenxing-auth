#![allow(dead_code)]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::SET_COOKIE},
};
use chenxing_auth::{api, config::Config, redis_keyspace::RedisKeyspace, state::AppState};
use serde_json::Value;
use tower::ServiceExt;

#[path = "key_directory.rs"]
mod key_directory;

pub fn isolated_key_directory(label: &str) -> std::path::PathBuf {
    key_directory::isolated_key_directory(label)
}

#[path = "qps_window.rs"]
pub mod qps_window;

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
    test_state_with_max_connections(binary_name, 2).await
}

/// Test-state variant for deterministic lock races that need more than the default two
/// connections.
pub async fn test_state_with_max_connections(
    binary_name: &str,
    max_connections: u32,
) -> (AppState, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    test_state_with_max_connections_and_keyspace(
        binary_name,
        max_connections,
        RedisKeyspace::default(),
    )
    .await
}

/// Test-state variant with an explicit Redis isolation boundary.
pub async fn test_state_with_max_connections_and_keyspace(
    binary_name: &str,
    max_connections: u32,
    redis_keyspace: RedisKeyspace,
) -> (AppState, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = crate::db_isolation::isolated_pool_with_max_connections(
        binary_name,
        &database_url,
        max_connections,
    )
    .await;
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
    config.redis_keyspace = redis_keyspace;
    let mut state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state");
    // QPS 窗口放大到 60s，限流断言不再依赖请求跑得够快（见 `qps_window`）。
    qps_window::override_qps_window(&mut state);
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
    // 公开注册默认关闭（registration 设置双 false 初始值）：闸门在输入校验之前，
    // 合法与非法请求都先撞 403 registration_disabled。
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "registration response: {body}"
    );
    assert_eq!(body["code"], "registration_disabled");

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

pub async fn ensure_owner_bootstrapped(
    router: &Router,
    pool: &chenxing_auth::sqlx::PgPool,
    binary_name: &str,
    suffix: &str,
) {
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
    // bootstrap 会把 users 序列重置回 1（生产语义：首个 Owner 固定 id=1），
    // 必须重新施加身份派生的用户 ID 偏移，否则后续创建的用户拿到小号 ID，
    // 按 user_id 命名的 Redis 键（TOTP 时间步 claim、会话吊销）会在并行
    // 测试之间碰撞。收敛到这一个入口，测试就无需各自记得调用。
    crate::db_isolation::isolate_user_ids(pool, binary_name).await;
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
