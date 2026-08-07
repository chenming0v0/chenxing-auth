//! 授权失败审计日志集成测试（Issue #73）
//!
//! 验证已认证用户在管理端点遭遇授权失败时，`audit_events` 中写入
//! `admin_authorization_denied` 事件，覆盖权限不足和 CSRF 校验失败两条拒绝路径。
//!
//! 本测试需要真实的 PostgreSQL 与 Redis，连接串取自 `DATABASE_URL` / `REDIS_URL`。

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    audit::{AuditEvent, AuditService},
    config::Config,
    sessions::{cookies, domain::Session, store::SessionStore},
    state::AppState,
};
use tower::ServiceExt;
use uuid::Uuid;

const DENIED_ACTION: &str = "admin_authorization_denied";

#[path = "support/db_isolation.rs"]
mod db_isolation;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned())
}

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = database_url();
    let redis_url = redis_url();
    let database = db_isolation::isolated_pool("authorization_audit", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-authz-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "authz-audit-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(
            AppState::new_with_pool(config, database.clone())
                .await
                .expect("state"),
        ),
        database,
        key_directory,
    )
}

/// 直接在 Redis/PG 里种一个已认证会话，跳过登录流程。
async fn browser_session(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> (String, String) {
    let redis = redis::Client::open(redis_url()).expect("Redis");
    let store = SessionStore::with_metadata_and_key(redis, database.clone(), [0; 32]);
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("browser session");
    store
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("save browser session");
    let cookie = format!(
        "{}={}; {}={}",
        cookies::session_cookie_name(false),
        session.token,
        cookies::csrf_cookie_name(false),
        session.csrf_token
    );
    (cookie, session.csrf_token)
}

/// 直接插入用户行。
///
/// 不走 `/api/v1/users` 注册接口：那条路径受 `app_settings.email_policy` 影响，
/// 而设置类测试位于另一个测试二进制中，`serial_test` 无法跨二进制串行化。
/// 这里只需要一行 `status='active'` 的用户供 session 解析，密码哈希不参与断言。
async fn seed_user(database: &chenxing_auth::sqlx::PgPool, name: &str, role: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar::<_, i64>(
        "INSERT INTO users (username, email, password_hash, role, status)
         VALUES ($1, $2, 'not-a-real-hash', $3, 'active')
         RETURNING id",
    )
    .bind(name)
    .bind(format!("{name}@example.com"))
    .bind(role)
    .fetch_one(database)
    .await
    .expect("seed user")
}

async fn denial_events(database: &chenxing_auth::sqlx::PgPool) -> Vec<AuditEvent> {
    let (events, _total) = AuditService::new(database.clone())
        .query(Some(DENIED_ACTION), None, 100, 0)
        .await
        .expect("audit query");
    events
}

#[tokio::test]
async fn insufficient_role_denial_is_recorded_in_the_audit_log() {
    let (router, database, _key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = seed_user(&database, &format!("plain-{suffix}"), "user").await;
    let (cookie, _csrf) = browser_session(&database, user_id).await;

    // 修复前：这里返回 403 但审计表为空，低权限用户可无痕探测所有 admin 端点。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("low privilege request"),
        )
        .await
        .expect("low privilege response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let events = denial_events(&database).await;
    assert_eq!(events.len(), 1, "授权失败必须留下且仅留下一条审计事件");
    let event = &events[0];
    assert_eq!(event.action, DENIED_ACTION);
    assert_eq!(event.actor_type, "user");
    assert_eq!(event.actor_id, Some(user_id.to_string()));
    assert_eq!(event.resource_type, "admin_permission");
    assert_eq!(event.resource_id.as_deref(), Some("ManageUsers"));
    assert_eq!(event.metadata["result"], "failure");
    assert_eq!(event.metadata["reason"], "insufficient_role");
}

#[tokio::test]
async fn csrf_denial_on_admin_mutation_is_recorded_in_the_audit_log() {
    let (router, database, _key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_id = seed_user(&database, &format!("owner-{suffix}"), "owner").await;
    let target_id = seed_user(&database, &format!("target-{suffix}"), "user").await;
    // Owner 权限充足，但故意不带 X-CSRF-Token 头，命中 current_admin_mutation 的 CSRF 分支。
    let (cookie, _csrf) = browser_session(&database, owner_id).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{target_id}/role"))
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "admin"}).to_string()))
                .expect("csrf-less mutation request"),
        )
        .await
        .expect("csrf-less mutation response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let events = denial_events(&database).await;
    assert_eq!(events.len(), 1, "CSRF 失败必须留下审计事件");
    let event = &events[0];
    assert_eq!(event.actor_id, Some(owner_id.to_string()));
    assert_eq!(event.resource_type, "admin_permission");
    assert_eq!(event.resource_id.as_deref(), Some("ManageRoles"));
    assert_eq!(event.metadata["reason"], "csrf_invalid");
}

#[tokio::test]
async fn audit_metadata_never_carries_session_or_csrf_credentials() {
    let (router, database, _key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = seed_user(&database, &format!("probe-{suffix}"), "user").await;
    let (cookie, csrf) = browser_session(&database, user_id).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .expect("probe request"),
        )
        .await
        .expect("probe response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let events = denial_events(&database).await;
    assert_eq!(events.len(), 1);
    let serialized = serde_json::to_string(&events[0]).expect("event serializes");
    assert!(!serialized.contains(&csrf), "审计事件不得包含 CSRF 令牌");
    for cookie_part in cookie.split("; ") {
        let value = cookie_part
            .split_once('=')
            .map(|(_, value)| value)
            .unwrap_or(cookie_part);
        assert!(
            !serialized.contains(value),
            "审计事件不得包含会话 Cookie 值"
        );
    }
}
