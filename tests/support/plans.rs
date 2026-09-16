#![allow(dead_code)]

//! `tests/storage/plans.rs` 的脚手架：状态构造、HTTP 辅助和套餐前提。
//!
//! 每个测试的套餐前提**写在测试里**：[`test_state`] 只保证一个已知的起点
//! （清空 + 播种原种子等价的默认套餐），需要「没有套餐」的测试自己调
//! [`clear_all_plans`]。

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD};
use chenxing_auth::{
    api, config::Config, oauth::authorization::ValidatedAuthorizationRequest,
    redis_keyspace::RedisKeyspace, sessions::domain::Session, state::AppState,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tower::ServiceExt;

/// QPS 窗口注入的规范实例由 `oauth_flow` 声明；这里公开转发，保留
/// `plans_support::qps_window` 路径，同时避免同一测试目标重复加载
/// `qps_window.rs`（`clippy::duplicate_mod`）。
pub use super::oauth_flow::qps_window;

#[path = "plan_fixtures.rs"]
pub mod fixtures;

#[path = "plans_admin.rs"]
mod admin;

pub use admin::{
    archive_plan, assign_plan, create_plan, list_plans, plan_limits, restore_plan, submit_plan,
    update_plan,
};

pub use fixtures::{
    DEFAULT_PLAN_CODE, active_default_plan_count, clear_all_plans, plan_status_and_default,
    seed_default_plan,
};

pub const ADMIN_TOKEN: &str = "plans-admin-token";
pub const REDIRECT_URI: &str = "https://plan.example/callback";

/// 一个套餐测试的运行环境。
///
/// 套餐前提由隔离保证：默认走 schema 隔离（见 `support/db_isolation.rs`），
/// `plans` 表存在于本二进制私有的 schema 中；显式选择模板路径时则是本测试私有
/// 的数据库克隆。两种方式下 [`clear_all_plans`] 都只影响自己，不需要跨二进制锁。
/// `default_plan_id` 是 [`test_state`] 播种的默认套餐 id，不把 identity 序列值当作
/// 测试契约。
///
/// 数据库隔离不足以隔离 Redis：退款 worker 会扫描全局队列，把仍在等待的
/// reservation 退款给其它测试。因此模板路径还额外为本测试签发一个独立的
/// [`RedisKeyspace`]，让所有 Redis 存储（含退款队列）互不可见。
pub struct PlanTestEnv {
    pub state: AppState,
    pub database: chenxing_auth::sqlx::PgPool,
    pub key_directory: std::path::PathBuf,
    pub default_plan_id: i64,
}

impl PlanTestEnv {
    pub fn router(&self) -> Router {
        api::router(self.state.clone())
    }

    /// 删除测试创建的套餐和专用密钥目录。测试结尾调用。
    pub async fn cleanup(&self) {
        clear_all_plans(&self.database).await;
        let _ = std::fs::remove_dir_all(&self.key_directory);
    }
}

/// 构造测试状态，并把套餐前提重置为「只有一个原种子等价的 active 默认套餐」。
///
/// 即使迁移提供了种子，这里仍显式清空后播种；需要「没有任何套餐」的测试在拿到
/// 环境后自己调 [`clear_all_plans`]。默认走 schema 隔离：本二进制私有的 schema。
pub async fn test_state() -> PlanTestEnv {
    test_state_with_max_connections(2).await
}

/// 构造测试状态，使用已迁移的模板数据库克隆而不是 schema 隔离（issue #710）。
///
/// 与 [`test_state`] 相同的 URL 读取与默认值，但 pool 来自
/// `isolated_pool_from_template_with_max_connections`，固定 2 个连接，并为本测试
/// 签发一个新的 [`RedisKeyspace`]，避免退款 worker 扫描到其它测试的 pending
/// reservation。模板命名空间缺失时 fail-closed，不回退到 schema 路径。
pub async fn test_state_from_template() -> PlanTestEnv {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = super::db_isolation::isolated_pool_from_template_with_max_connections(
        "plans",
        &database_url,
        2,
    )
    .await;
    let redis_keyspace = RedisKeyspace::new(&format!("plans-{}", uuid::Uuid::new_v4().simple()))
        .expect("test Redis namespace");
    finish_plan_env(database, database_url, redis_url, redis_keyspace).await
}

/// Construct a plan test environment with an explicit pool size for tests that
/// need a blocker, a blocked request, and an independent mutator at once.
///
/// 保持既有 schema 路径行为：沿用默认（legacy）Redis key 空间。
pub async fn test_state_with_max_connections(max_connections: u32) -> PlanTestEnv {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = super::db_isolation::isolated_pool_with_max_connections(
        "plans",
        &database_url,
        max_connections,
    )
    .await;
    finish_plan_env(database, database_url, redis_url, RedisKeyspace::default()).await
}

/// 从已建立的 pool 完成公共初始化：清空并播种默认套餐、密钥目录、配置、
/// AppState 注入和 QPS 覆盖。两种 pool 来源（schema / 模板克隆）共用。
///
/// `redis_keyspace` 在 `AppState::new_with_pool` 之前写入 config，因此所有 Redis
/// 存储都继承它；schema 路径传 [`RedisKeyspace::default`]，行为与改动前一致。
async fn finish_plan_env(
    database: chenxing_auth::sqlx::PgPool,
    database_url: String,
    redis_url: String,
    redis_keyspace: RedisKeyspace,
) -> PlanTestEnv {
    clear_all_plans(&database).await;
    let default_plan_id = seed_default_plan(&database).await;
    let key_directory = super::key_directory::isolated_key_directory("plans");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.admin_token = ADMIN_TOKEN.to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    config.redis_keyspace = redis_keyspace;
    let mut state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state");
    // QPS 窗口放大到 60s，套餐限流断言不再依赖两发请求跑得够快（见 `qps_window`）。
    qps_window::override_qps_window(&mut state);
    PlanTestEnv {
        state,
        database,
        key_directory,
        default_plan_id,
    }
}

pub async fn json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

pub async fn bootstrap_owner(router: &Router, suffix: &str) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("plan-owner-{suffix}"),
                        "email": format!("plan-owner-{suffix}@example.com"),
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
        "unexpected bootstrap status: {}",
        response.status()
    );
}

pub async fn register_user(router: &Router, suffix: &str) -> i64 {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("plan-user-{suffix}"),
                        "email": format!("plan-user-{suffix}@example.com"),
                        "password": "correct horse battery",
                    })
                    .to_string(),
                ))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::CREATED);
    json(response).await["id"]
        .as_i64()
        .expect("numeric user id")
}

pub async fn persisted_user_session_with_ttl(
    state: &AppState,
    user_id: i64,
    ttl: Duration,
) -> Session {
    let mut session = Session::new(user_id.to_string(), ttl).expect("browser session");
    state
        .sessions
        .save(&mut session, ttl)
        .await
        .expect("persist session");
    session
}

pub async fn persisted_user_session(state: &AppState, user_id: i64) -> Session {
    persisted_user_session_with_ttl(state, user_id, Duration::from_secs(3600)).await
}

pub async fn user_session(state: &AppState, user_id: i64) -> (String, String) {
    let session = persisted_user_session(state, user_id).await;
    let cookie = format!(
        "chenxing_session={}; chenxing_csrf={}",
        session.token, session.csrf_token
    );
    (cookie, session.csrf_token)
}

/// 发起自助创建 Client 的请求，返回原始响应（用于断言 403 等失败状态）。
pub async fn post_owned_client(
    router: &Router,
    cookie: &str,
    csrf: &str,
    suffix: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": format!("Plan Client {suffix}"),
                        "redirect_uris": [REDIRECT_URI],
                        "scopes": ["openid", "profile", "email"],
                    })
                    .to_string(),
                ))
                .expect("owned client request"),
        )
        .await
        .expect("owned client response")
}

pub async fn create_owned_client(router: &Router, cookie: &str, csrf: &str, suffix: &str) -> Value {
    let response = post_owned_client(router, cookie, csrf, suffix).await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "owned client creation: {}",
        response.status()
    );
    json(response).await
}

/// 通过管理接口创建 Client：stamp 到第一个未禁用 Owner（没有 Owner 时才为 NULL），
/// 不走自助额度。没有生效套餐时授权/换令牌仍成功。
pub async fn create_admin_client(router: &Router, suffix: &str) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": format!("Admin Client {suffix}"),
                        "redirect_uris": [REDIRECT_URI],
                        "scopes": ["openid", "profile", "email"],
                    })
                    .to_string(),
                ))
                .expect("admin client request"),
        )
        .await
        .expect("admin client response");
    assert_eq!(response.status(), StatusCode::CREATED, "admin client");
    json(response).await
}

pub async fn get_entitlements(router: &Router, cookie: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/entitlements")
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("entitlements request"),
        )
        .await
        .expect("entitlements response");
    let status = response.status();
    (status, json(response).await)
}

pub async fn list_owned_clients(router: &Router, cookie: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("owned client list request"),
        )
        .await
        .expect("owned client list response");
    let status = response.status();
    (status, json(response).await)
}

pub fn validated_request(client_id: &str, user_id: i64) -> ValidatedAuthorizationRequest {
    validated_request_with_challenge(client_id, user_id, "plan-challenge")
}

/// 需要真正兑换令牌的用例必须给出 S256 challenge —— Token 端点会校验
/// `code_verifier`，随手写的字符串过不了 PKCE。
pub fn validated_request_with_challenge(
    client_id: &str,
    user_id: i64,
    code_challenge: &str,
) -> ValidatedAuthorizationRequest {
    ValidatedAuthorizationRequest {
        client_id: client_id.to_owned(),
        redirect_uri: REDIRECT_URI.to_owned(),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        state: "plan-state".to_owned(),
        nonce: None,
        code_challenge: code_challenge.to_owned(),
        prompt: None,
        max_age: None,
        reauth_required: false,
        reauth_session_token_hash: None,
        owner_user_id: Some(user_id),
        session_token_hash: None,
    }
}

/// PKCE `code_verifier` → S256 `code_challenge`。
pub fn code_challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// 从 authorize 重定向 URL 中取出授权码。
pub fn authorization_code_from_redirect(redirect: &str) -> String {
    url::Url::parse(redirect)
        .expect("authorization redirect URL")
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .expect("authorization code in redirect")
}

/// 用 client_secret_basic 兑换授权码。
pub async fn exchange_authorization_code(
    router: &Router,
    client_id: &str,
    client_secret: &str,
    code: &str,
    verifier: &str,
) -> (StatusCode, Value) {
    let credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("code_verifier", verifier)
        .finish();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {credentials}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("token request"),
        )
        .await
        .expect("token response");
    let status = response.status();
    (status, json(response).await)
}
