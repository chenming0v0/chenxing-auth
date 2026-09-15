#![allow(dead_code)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::SET_COOKIE},
};
use chenxing_auth::{api, redis_keyspace::RedisKeyspace, state::AppState};
use tower::ServiceExt;

#[path = "qps_window.rs"]
pub mod qps_window;

/// 转发到每个测试目标在 crate 根声明的唯一 `key_directory` 实例，保留历史公开入口。
/// 目标 `mod.rs` 必须以 `#[path = "../support/key_directory.rs"] mod key_directory;`
/// 声明该实例，本模块再通过 `super::key_directory` 使用它。
pub fn isolated_key_directory(label: &str) -> std::path::PathBuf {
    super::key_directory::isolated_key_directory(label)
}

/// 读取响应体并解析为 JSON；实现委托给 [`super::http::json_body`]，保留本模块
/// 的历史公开入口名。
pub use super::http::json_body;

/// `binary_name` 决定 schema 隔离边界，必须传调用方使用的稳定隔离标签
/// （见 `support/db_isolation.rs`）。共享同一个名字的测试会共享数据库状态。
///
/// 调用方必须同时声明 `db_isolation` 与 crate 根的 `key_directory` 模块：
/// ```rust,ignore
/// #[path = "../support/db_isolation.rs"]
/// mod db_isolation;
/// #[path = "../support/key_directory.rs"]
/// mod key_directory;
/// #[path = "../support/oauth_flow.rs"]
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
///
/// 委托给 [`super::harness::HarnessBuilder`]，避免各入口重复拼装 Config / AppState。
/// 保留历史语义：`flow-admin-token`、`cookie_secure = false`、并注入测试用 QPS 大窗口
/// （见 `qps_window`）。需要关闭窗口注入的用例请直接用 `HarnessBuilder`，不要经过本入口。
pub async fn test_state_with_max_connections_and_keyspace(
    binary_name: &str,
    max_connections: u32,
    redis_keyspace: RedisKeyspace,
) -> (AppState, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let (state, database, key_directory, _admin_token, _binary_name) =
        super::harness::HarnessBuilder::new(binary_name)
            .admin_token("flow-admin-token")
            .max_connections(max_connections)
            .redis_keyspace(redis_keyspace)
            .qps_window_override()
            .build_state()
            .await;
    (state, database, key_directory)
}

pub async fn test_router(
    binary_name: &str,
) -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let (state, database, key_directory) = test_state(binary_name).await;
    (api::router(state), database, key_directory)
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
    // 把后续用户 ID 保持在测试身份派生的高位区间，避免按 user_id 命名的 Redis
    // 键（TOTP 时间步 claim、会话吊销）在并行测试之间碰撞。引导不再把序列打回
    // 1：隔离 schema 已分配的 Owner identity 必须保留，isolate_user_ids 只向前
    // 推进。收敛到这一个入口，测试就无需各自记得调用。
    super::db_isolation::isolate_user_ids(pool, binary_name).await;
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
