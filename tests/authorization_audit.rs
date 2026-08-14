//! 授权失败审计日志集成测试（Issue #73）
//!
//! 验证已认证用户在管理端点遭遇授权失败时，`audit_events` 中写入
//! `admin_authorization_denied` 事件，覆盖权限不足和 CSRF 校验失败两条拒绝路径。
//!
//! Issue #280 起还覆盖授权与资源查询的顺序：以用户为目标的管理写操作必须先按
//! 与目标无关的基线权限授权，低权限调用者因此无法用「403 说的是哪个权限」
//! 枚举目标用户是否存在、是否是 Owner。
//!
//! 本测试需要真实的 PostgreSQL 与 Redis，连接串取自 `DATABASE_URL` / `REDIS_URL`。

use axum::{
    Router,
    body::{Body, to_bytes},
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
/// Issue #304：领域守卫拒绝的 action，与权限拒绝分开检索。
const GUARD_DENIED_ACTION: &str = "admin_owner_guard_denied";

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
        "INSERT INTO users (username, email, canonical_email, password_hash, role, status)
         VALUES ($1, $2, lower($2), 'not-a-real-hash', $3, 'active')
         RETURNING id",
    )
    .bind(name)
    .bind(format!("{name}@example.com"))
    .bind(role)
    .fetch_one(database)
    .await
    .expect("seed user")
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn denial_events(database: &chenxing_auth::sqlx::PgPool) -> Vec<AuditEvent> {
    events_for_action(database, DENIED_ACTION).await
}

async fn guard_denial_events(database: &chenxing_auth::sqlx::PgPool) -> Vec<AuditEvent> {
    events_for_action(database, GUARD_DENIED_ACTION).await
}

async fn events_for_action(
    database: &chenxing_auth::sqlx::PgPool,
    action: &str,
) -> Vec<AuditEvent> {
    let (events, _total) = AuditService::new(database.clone())
        .query(Some(action), None, 100, 0)
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
    assert_eq!(event.resource_id.as_deref(), Some("ManageUsers"));
    assert_eq!(event.metadata["reason"], "csrf_invalid");
}

/// Issue #280：低权限调用者不得把权限门槛当作资源存在性预言机。
///
/// 修复前 `set_user_status` 先查目标用户角色再决定需要 `ManageUsers` 还是
/// `ManageRoles`，于是一个只有 `user` 角色的账号可以逐个 id 发请求，从审计里
/// 记下的权限名（以及那次必然发生的数据库查询）读出「这个 id 存在且是 Owner」。
/// 现在三种目标 —— Owner、普通用户、不存在的 id —— 必须给出完全相同的拒绝，
/// 且留痕的权限恒为基线 `ManageUsers`。
#[tokio::test]
async fn low_privilege_status_probe_cannot_enumerate_owners_or_missing_users() {
    let (router, database, _key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_id = seed_user(&database, &format!("owner-{suffix}"), "owner").await;
    let plain_id = seed_user(&database, &format!("plain-{suffix}"), "user").await;
    let prober_id = seed_user(&database, &format!("prober-{suffix}"), "user").await;
    // 目标 id 必然不存在：同 schema 内的序列按 1 递增，偏移 100 万不会撞上。
    let missing_id = owner_id + 1_000_000;
    let (cookie, csrf) = browser_session(&database, prober_id).await;

    for target in [owner_id, plain_id, missing_id] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/admin/users/{target}/disabled"))
                    .header("cookie", &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .expect("probe request"),
            )
            .await
            .expect("probe response");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "target {target} must be indistinguishable"
        );
        assert_eq!(json(response).await["code"], "admin_forbidden");
    }

    let events = denial_events(&database).await;
    assert_eq!(events.len(), 3, "三次探测各留一条审计事件");
    for event in &events {
        assert_eq!(event.actor_id, Some(prober_id.to_string()));
        assert_eq!(event.metadata["reason"], "insufficient_role");
        // 恒为基线权限：ManageRoles 出现在这里就意味着门槛又变成了资源状态的函数。
        assert_eq!(
            event.resource_id.as_deref(),
            Some("ManageUsers"),
            "拒绝理由不得随目标用户的角色变化"
        );
    }
}

/// Issue #283：非法状态与用户不存在必须是两个不同的结构化错误。
///
/// 修复前两者共用 `400 user_not_found`（"user or status was not found"），
/// 调用方无法区分「我把状态拼错了」和「这个用户没了」。
#[tokio::test]
async fn invalid_status_and_missing_user_are_separate_structured_errors() {
    let (router, database, _key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let target_id = seed_user(&database, &format!("target-{suffix}"), "user").await;
    let missing_id = target_id + 1_000_000;

    let post = |path: String| {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", "Bearer authz-audit-token")
                .body(Body::empty())
                .expect("status mutation request"),
        )
    };

    // 存在的用户 + 非法状态串 → 400 invalid_status
    let response = post(format!("/api/v1/admin/users/{target_id}/bogus"))
        .await
        .expect("invalid status response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "invalid_status");

    // 不存在的用户 + 非法状态串 → 仍是 400：状态串是与资源无关的语法输入，
    // 在查询目标之前就被拒，因此不会退化成 404。
    let response = post(format!("/api/v1/admin/users/{missing_id}/bogus"))
        .await
        .expect("invalid status for missing user response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "invalid_status");

    // 不存在的用户 + 合法状态串 → 404 user_not_found
    let response = post(format!("/api/v1/admin/users/{missing_id}/disabled"))
        .await
        .expect("missing user response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(json(response).await["code"], "user_not_found");

    // 合法状态串 + 存在的用户 → 204，确认上面三条不是把整条路径都拒掉了
    let response = post(format!("/api/v1/admin/users/{target_id}/disabled"))
        .await
        .expect("valid status response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

/// Issue #280：改写 Owner 的套餐与禁用 Owner 同档，都要求 `ManageRoles`。
///
/// 修复前 `assign_plan` 只要 `ManageUsers`，因此一个 Admin 可以把 Owner 的套餐
/// 换成配额最小的那个，压缩最高权限持有者的 Client 数量与授权额度。
/// 抬档必须只针对 Owner：同一个 Admin 改普通用户的套餐仍然走得通。
#[tokio::test]
async fn assigning_a_plan_to_an_owner_requires_manage_roles() {
    let (router, database, _key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_id = seed_user(&database, &format!("owner-{suffix}"), "owner").await;
    let plain_id = seed_user(&database, &format!("plain-{suffix}"), "user").await;
    // Admin 有 ManageUsers，没有 ManageRoles。
    let admin_id = seed_user(&database, &format!("admin-{suffix}"), "admin").await;
    let (cookie, csrf) = browser_session(&database, admin_id).await;
    // 套餐 id 故意不存在：403 必须在触达套餐之前发生，否则断言会退化成 404。
    let missing_plan_id = 999_999_999_i64;

    let assign = |target: i64| {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{target}/plan"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"plan_id": missing_plan_id, "expires_at": null}).to_string(),
                ))
                .expect("assign plan request"),
        )
    };

    let response = assign(owner_id).await.expect("owner assign response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json(response).await["code"], "admin_forbidden");

    // 普通用户不抬档：同一个 Admin 走到套餐查询，因此拿到 404 plan_not_found。
    let response = assign(plain_id).await.expect("plain assign response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(json(response).await["code"], "plan_not_found");

    let events = denial_events(&database).await;
    assert_eq!(events.len(), 1, "只有 Owner 目标那一次留下拒绝记录");
    assert_eq!(events[0].actor_id, Some(admin_id.to_string()));
    assert_eq!(events[0].resource_id.as_deref(), Some("ManageRoles"));
    assert_eq!(events[0].metadata["reason"], "insufficient_role");
}

/// Issue #304：Owner 守卫拒绝必须留下结构化审计，且与权限拒绝分开。
///
/// 修复前这条路径只返回 409，审计表里什么都没有 —— 一个具备 `ManageRoles` 的
/// 主体反复尝试移除仅存的 Owner（操作失误或接管企图）在事后完全不可见。
/// 两条受守卫保护的写路径（禁用、降级）都要留痕，且四个事实齐全：
/// actor、target、operation、reason。
#[tokio::test]
async fn last_owner_guard_denials_are_recorded_with_actor_target_and_operation() {
    let (router, database, _key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_id = seed_user(&database, &format!("owner-{suffix}"), "owner").await;

    // 系统 Token 禁用唯一的活跃 Owner：守卫拒绝，必须留痕。
    // 浏览器会话的 Owner 自我操作已被 self_status_change_forbidden 拦掉，
    // 与角色变更一样改用系统 Token 触达守卫（Issue #336）。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{owner_id}/disabled"))
                .header("authorization", "Bearer authz-audit-token")
                .body(Body::empty())
                .expect("disable last owner request"),
        )
        .await
        .expect("disable last owner response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "last_owner_required");

    let events = guard_denial_events(&database).await;
    assert_eq!(events.len(), 1, "禁用最后一个 Owner 必须留下一条审计事件");
    let event = &events[0];
    assert_eq!(event.action, GUARD_DENIED_ACTION);
    assert_eq!(event.actor_type, "system_token");
    assert_eq!(event.actor_id, None);
    assert_eq!(event.resource_type, "user");
    assert_eq!(
        event.resource_id,
        Some(owner_id.to_string()),
        "target 必须是被操作的用户，而不是权限名"
    );
    assert_eq!(event.metadata["result"], "failure");
    assert_eq!(event.metadata["reason"], "last_owner_required");
    assert_eq!(event.metadata["operation"], "user_status_update");
    assert_eq!(event.metadata["requested"], "disabled");

    // 降级最后一个 Owner 走同一条留痕路径，但 operation 不同。
    // 自改角色被更早的守卫拦掉，所以用系统 Token 作为 actor。
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{owner_id}/role"))
                .header("authorization", "Bearer authz-audit-token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "user"}).to_string()))
                .expect("demote last owner request"),
        )
        .await
        .expect("demote last owner response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "last_owner_required");

    let events = guard_denial_events(&database).await;
    assert_eq!(events.len(), 2, "降级最后一个 Owner 同样必须留痕");
    let event = events
        .iter()
        .find(|event| event.metadata["operation"] == "user_role_update")
        .expect("role update denial event");
    // 系统 Token 没有用户 id：审计如实记录 actor_type 而不是伪造一个用户。
    assert_eq!(event.actor_type, "system_token");
    assert_eq!(event.actor_id, None);
    assert_eq!(event.resource_id, Some(owner_id.to_string()));
    assert_eq!(event.metadata["reason"], "last_owner_required");
    assert_eq!(event.metadata["requested"], "user");

    // 守卫拒绝不得混进权限拒绝：两者 action 不同，后者这里必须为空。
    assert!(
        denial_events(&database).await.is_empty(),
        "领域守卫拒绝不能被记成 admin_authorization_denied"
    );

    // Owner 仍然是活跃 Owner：拒绝路径不得改变任何状态。
    let (role, status): (String, String) =
        chenxing_auth::sqlx::query_as("SELECT role, status FROM users WHERE id = $1")
            .bind(owner_id)
            .fetch_one(&database)
            .await
            .expect("owner row after denials");
    assert_eq!((role.as_str(), status.as_str()), ("owner", "active"));
}

/// 守卫拒绝的审计元数据不得携带请求凭据。
///
/// `requested` 是封闭词表里的枚举值（状态或角色），不是自由文本；这条测试
/// 防止日后有人把整个请求体塞进元数据。
#[tokio::test]
async fn owner_guard_denial_metadata_carries_no_credentials() {
    let (router, database, _key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_id = seed_user(&database, &format!("owner-{suffix}"), "owner").await;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{owner_id}/disabled"))
                .header("authorization", "Bearer authz-audit-token")
                .body(Body::empty())
                .expect("disable last owner request"),
        )
        .await
        .expect("disable last owner response");
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let events = guard_denial_events(&database).await;
    assert_eq!(events.len(), 1);
    let serialized = serde_json::to_string(&events[0]).expect("event serializes");
    assert!(
        !serialized.contains("authz-audit-token"),
        "审计事件不得包含管理员令牌"
    );
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
