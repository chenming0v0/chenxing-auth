//! Issue #474：特权账号创建和角色提升必须与持久审计同行提交。
//!
//! #304 覆盖 Owner 引导。本文件覆盖后续授予路径：
//! `POST /api/v1/admin/admins`、特权 `POST /api/v1/admin/users`、
//! `POST /api/v1/admin/users/{id}/role`。
//!
//! 制造审计故障的手法与 client / settings 测试相同：在隔离 schema 里给
//! `audit_events` 加 BEFORE INSERT 触发器，只拒绝特权授予相关 action。
//! `users` 表保持可写，因此失败时若仍提交，用户行或角色变更会残留。

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    audit::{AuditEvent, AuditService},
    config::Config,
    state::AppState,
};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

const ADMIN_TOKEN: &str = "privileged-audit-token";
const PASSWORD: &str = "1234567890";

async fn setup() -> (
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("privileged_audit", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("privileged-audit");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = ADMIN_TOKEN.to_owned();
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

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("JSON")
}

fn authorized(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("authorized request")
}

async fn bootstrap_owner(router: &axum::Router, suffix: &str) -> i64 {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("owner-{suffix}"),
                        "email": format!("owner-{suffix}@example.com"),
                        "password": PASSWORD
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    json(response).await["id"].as_i64().expect("owner id")
}

async fn seed_user(database: &chenxing_auth::sqlx::PgPool, name: &str, role: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar(
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

async fn user_count(database: &chenxing_auth::sqlx::PgPool, username: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1")
        .bind(username)
        .fetch_one(database)
        .await
        .expect("user count")
}

async fn user_role(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> String {
    chenxing_auth::sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("user role")
}

async fn events_for(database: &chenxing_auth::sqlx::PgPool, action: &str) -> Vec<AuditEvent> {
    let (events, _total) = AuditService::new(database.clone())
        .query(Some(action), None, 100, 0)
        .await
        .expect("audit query");
    events
}

async fn install_privileged_audit_failure(database: &chenxing_auth::sqlx::PgPool) {
    chenxing_auth::sqlx::query(
        "CREATE FUNCTION reject_privileged_grant_audit() RETURNS trigger
         LANGUAGE plpgsql AS $$
         BEGIN
             IF NEW.action IN ('user_create', 'user_role_update') THEN
                 RAISE EXCEPTION 'injected privileged grant audit failure';
             END IF;
             RETURN NEW;
         END;
         $$",
    )
    .execute(database)
    .await
    .expect("audit failure function");
    chenxing_auth::sqlx::query(
        "CREATE TRIGGER reject_privileged_grant_audit
         BEFORE INSERT ON audit_events
         FOR EACH ROW EXECUTE FUNCTION reject_privileged_grant_audit()",
    )
    .execute(database)
    .await
    .expect("audit failure trigger");
}

async fn remove_privileged_audit_failure(database: &chenxing_auth::sqlx::PgPool) {
    chenxing_auth::sqlx::query("DROP TRIGGER reject_privileged_grant_audit ON audit_events")
        .execute(database)
        .await
        .expect("drop audit failure trigger");
    chenxing_auth::sqlx::query("DROP FUNCTION reject_privileged_grant_audit()")
        .execute(database)
        .await
        .expect("drop audit failure function");
}

fn assert_system_token_grant(event: &AuditEvent, resource_id: i64, role: &str) {
    assert_eq!(event.actor_type, "system_token");
    assert_eq!(event.actor_id, None);
    assert_eq!(event.resource_type, "user");
    assert_eq!(
        event.resource_id.as_deref(),
        Some(resource_id.to_string().as_str())
    );
    assert_eq!(event.metadata["role"], role);
    let serialized = serde_json::to_string(event).expect("event serializes");
    assert!(
        !serialized.contains(PASSWORD),
        "privileged grant audit must not record the password"
    );
}

/// 成功路径：权限变更与审计事件在同一次提交后同时可见。
#[tokio::test]
async fn privileged_mutations_share_a_commit_with_audit() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_id = bootstrap_owner(&router, &suffix).await;

    let admin_name = format!("grant-admin-{suffix}");
    let response = router
        .clone()
        .oneshot(authorized(
            "POST",
            "/api/v1/admin/admins",
            serde_json::json!({
                "username": admin_name,
                "email": format!("{admin_name}@example.com"),
                "password": PASSWORD,
                "role": "admin"
            }),
        ))
        .await
        .expect("create admin response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let admin_id = json(response).await["id"].as_i64().expect("admin id");
    assert_eq!(user_role(&database, admin_id).await, "admin");

    let owner_name = format!("grant-owner-{suffix}");
    let response = router
        .clone()
        .oneshot(authorized(
            "POST",
            "/api/v1/admin/users",
            serde_json::json!({
                "username": owner_name,
                "email": format!("{owner_name}@example.com"),
                "password": PASSWORD,
                "role": "owner"
            }),
        ))
        .await
        .expect("create privileged user response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let second_owner_id = json(response).await["id"]
        .as_i64()
        .expect("second owner id");
    assert_eq!(user_role(&database, second_owner_id).await, "owner");

    let creates = events_for(&database, "user_create").await;
    assert_eq!(
        creates.len(),
        2,
        "each privileged create must leave one audit row"
    );
    let admin_event = creates
        .iter()
        .find(|event| event.resource_id.as_deref() == Some(admin_id.to_string().as_str()))
        .expect("admin create audit");
    assert_system_token_grant(admin_event, admin_id, "admin");
    assert_eq!(admin_event.metadata["status"], "active");
    let owner_event = creates
        .iter()
        .find(|event| event.resource_id.as_deref() == Some(second_owner_id.to_string().as_str()))
        .expect("owner create audit");
    assert_system_token_grant(owner_event, second_owner_id, "owner");

    let target_id = seed_user(&database, &format!("promote-{suffix}"), "user").await;
    let response = router
        .clone()
        .oneshot(authorized(
            "POST",
            &format!("/api/v1/admin/users/{target_id}/role"),
            serde_json::json!({"role": "admin"}),
        ))
        .await
        .expect("promote response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(user_role(&database, target_id).await, "admin");

    let promotions = events_for(&database, "user_role_update").await;
    assert_eq!(promotions.len(), 1);
    assert_system_token_grant(&promotions[0], target_id, "admin");

    // 现在有两个 Owner：降级引导 Owner 必须成功并留下审计，最后一个仍受守卫保护。
    let response = router
        .clone()
        .oneshot(authorized(
            "POST",
            &format!("/api/v1/admin/users/{owner_id}/role"),
            serde_json::json!({"role": "admin"}),
        ))
        .await
        .expect("demote non-last owner response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(user_role(&database, owner_id).await, "admin");

    let response = router
        .oneshot(authorized(
            "POST",
            &format!("/api/v1/admin/users/{second_owner_id}/role"),
            serde_json::json!({"role": "user"}),
        ))
        .await
        .expect("demote last owner response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "last_owner_required");
    assert_eq!(user_role(&database, second_owner_id).await, "owner");

    let _ = std::fs::remove_dir_all(key_directory);
}

/// 审计 INSERT 失败时，Admin/Owner 不得被创建，角色也不得提升。
#[tokio::test]
async fn privileged_mutations_roll_back_when_audit_insert_fails() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_id = bootstrap_owner(&router, &suffix).await;
    let target_id = seed_user(&database, &format!("held-{suffix}"), "user").await;
    install_privileged_audit_failure(&database).await;

    let admin_name = format!("ghost-admin-{suffix}");
    let response = router
        .clone()
        .oneshot(authorized(
            "POST",
            "/api/v1/admin/admins",
            serde_json::json!({
                "username": admin_name,
                "email": format!("{admin_name}@example.com"),
                "password": PASSWORD,
                "role": "admin"
            }),
        ))
        .await
        .expect("create admin with broken audit");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(response).await["code"], "audit_unavailable");
    assert_eq!(user_count(&database, &admin_name).await, 0);

    let owner_name = format!("ghost-owner-{suffix}");
    let response = router
        .clone()
        .oneshot(authorized(
            "POST",
            "/api/v1/admin/users",
            serde_json::json!({
                "username": owner_name,
                "email": format!("{owner_name}@example.com"),
                "password": PASSWORD,
                "role": "owner"
            }),
        ))
        .await
        .expect("create owner with broken audit");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(response).await["code"], "audit_unavailable");
    assert_eq!(user_count(&database, &owner_name).await, 0);

    let response = router
        .clone()
        .oneshot(authorized(
            "POST",
            &format!("/api/v1/admin/users/{target_id}/role"),
            serde_json::json!({"role": "admin"}),
        ))
        .await
        .expect("promote with broken audit");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(response).await["code"], "audit_unavailable");
    assert_eq!(user_role(&database, target_id).await, "user");

    // 普通用户创建不走同事务审计，审计故障不得误伤这条路径。
    let regular_name = format!("plain-{suffix}");
    let response = router
        .clone()
        .oneshot(authorized(
            "POST",
            "/api/v1/admin/users",
            serde_json::json!({
                "username": regular_name,
                "email": format!("{regular_name}@example.com"),
                "password": PASSWORD
            }),
        ))
        .await
        .expect("regular user create");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(user_count(&database, &regular_name).await, 1);

    // 最后 Owner 守卫在审计 INSERT 之前判定，故障不得把它改写成 503。
    let response = router
        .clone()
        .oneshot(authorized(
            "POST",
            &format!("/api/v1/admin/users/{owner_id}/role"),
            serde_json::json!({"role": "user"}),
        ))
        .await
        .expect("last owner demotion with broken audit");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "last_owner_required");
    assert_eq!(user_role(&database, owner_id).await, "owner");

    assert!(events_for(&database, "user_create").await.is_empty());
    assert!(events_for(&database, "user_role_update").await.is_empty());

    remove_privileged_audit_failure(&database).await;
    let response = router
        .oneshot(authorized(
            "POST",
            "/api/v1/admin/admins",
            serde_json::json!({
                "username": admin_name,
                "email": format!("{admin_name}@example.com"),
                "password": PASSWORD,
                "role": "admin"
            }),
        ))
        .await
        .expect("retry create admin");
    assert_eq!(response.status(), StatusCode::CREATED);
    let admin_id = json(response).await["id"]
        .as_i64()
        .expect("retried admin id");
    let creates = events_for(&database, "user_create").await;
    assert_eq!(creates.len(), 1, "retry must persist the missing audit row");
    assert_system_token_grant(&creates[0], admin_id, "admin");

    let _ = std::fs::remove_dir_all(key_directory);
}
