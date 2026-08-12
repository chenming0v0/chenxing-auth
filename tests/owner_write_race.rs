//! Owner 目标管理写入的事务边界回归（Issue #323）。
//!
//! 两个用例都先在独立事务里把普通用户晋升为 Owner 并持有目标行锁，再发出只有
//! `ManageUsers` 的 Admin 请求。请求确认已阻塞在该事务后才提交晋升：这精确覆盖
//! 「事务外读到 user，写事务里实际已是 owner」的旧 TOCTOU 窗口。

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
use tokio::time::{sleep, timeout};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

struct TestEnv {
    router: Router,
    database: chenxing_auth::sqlx::PgPool,
    key_directory: std::path::PathBuf,
}

async fn setup() -> TestEnv {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    // 晋升事务、被测请求和锁等待探针必须能同时持有连接。
    let database = db_isolation::isolated_pool_with_max_connections(
        "owner_write_race",
        &database_url,
        6,
    )
    .await;
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-owner-write-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.admin_token = "issue-323-system-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state");
    TestEnv {
        router: api::router(state),
        database,
        key_directory,
    }
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

async fn browser_session(
    database: &chenxing_auth::sqlx::PgPool,
    user_id: i64,
) -> (String, String) {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = redis::Client::open(redis_url).expect("Redis");
    let store = SessionStore::with_metadata_and_key(redis, database.clone(), [0; 32]);
    let mut session = Session::new(user_id.to_string(), Duration::from_secs(3600))
        .expect("browser session");
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
    (cookie, session.csrf_token)
}

/// 等到被测请求确实在等待晋升事务，而不是靠 sleep 猜调度时序。
async fn wait_for_blocked_request(
    database: &chenxing_auth::sqlx::PgPool,
    blocker_pid: i32,
) {
    timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = chenxing_auth::sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1
                     FROM pg_stat_activity
                     WHERE $1 = ANY(pg_blocking_pids(pid))
                 )",
            )
            .bind(blocker_pid)
            .fetch_one(database)
            .await
            .expect("inspect PostgreSQL lock wait");
            if blocked {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("admin write never reached the promoted target row lock");
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn manage_roles_denial_count(
    database: &chenxing_auth::sqlx::PgPool,
    admin_id: i64,
) -> i64 {
    chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM audit_events
         WHERE actor_user_id = $1
           AND action = 'admin_authorization_denied'
           AND resource_id = 'ManageRoles'
           AND metadata->>'reason' = 'insufficient_role'",
    )
    .bind(admin_id)
    .fetch_one(database)
    .await
    .expect("ManageRoles denial count")
}

#[tokio::test]
async fn status_write_uses_the_owner_role_locked_by_its_write_transaction() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    // 两个既有 Owner 让旧实现不会被 LastOwnerRequired 偶然挡住；若权限竞态存在，
    // 它会真的禁用刚晋升的第三个 Owner。
    seed_user(&env.database, &format!("owner-a-{suffix}"), "owner").await;
    seed_user(&env.database, &format!("owner-b-{suffix}"), "owner").await;
    let target_id = seed_user(&env.database, &format!("target-{suffix}"), "user").await;
    let admin_id = seed_user(&env.database, &format!("admin-{suffix}"), "admin").await;
    let (cookie, csrf) = browser_session(&env.database, admin_id).await;

    let mut promotion = env.database.begin().await.expect("begin owner promotion");
    let blocker_pid: i32 = chenxing_auth::sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *promotion)
        .await
        .expect("promotion backend pid");
    chenxing_auth::sqlx::query("UPDATE users SET role = 'owner' WHERE id = $1")
        .bind(target_id)
        .execute(&mut *promotion)
        .await
        .expect("stage owner promotion");

    let router = env.router.clone();
    let request = tokio::spawn(async move {
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/admin/users/{target_id}/disabled"))
                    .header("cookie", cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .expect("status request"),
            )
            .await
            .expect("status response")
    });

    wait_for_blocked_request(&env.database, blocker_pid).await;
    promotion.commit().await.expect("commit owner promotion");
    let response = request.await.expect("status request task");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await["code"], "admin_forbidden");

    let state: (String, String) =
        chenxing_auth::sqlx::query_as("SELECT role, status FROM users WHERE id = $1")
            .bind(target_id)
            .fetch_one(&env.database)
            .await
            .expect("target state after denied status write");
    assert_eq!(state, ("owner".to_owned(), "active".to_owned()));
    assert_eq!(
        manage_roles_denial_count(&env.database, admin_id).await,
        1
    );
    let _ = std::fs::remove_dir_all(&env.key_directory);
}

#[tokio::test]
async fn plan_assignment_uses_the_owner_role_locked_by_its_write_transaction() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let target_id = seed_user(&env.database, &format!("target-{suffix}"), "user").await;
    let admin_id = seed_user(&env.database, &format!("admin-{suffix}"), "admin").await;
    let (cookie, csrf) = browser_session(&env.database, admin_id).await;
    let plan_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO plans (code, name, oauth_clients_limit, daily_auth_limit, status)
         VALUES ($1, 'Race regression', 1, 10, 'active')
         RETURNING id",
    )
    .bind(format!("race-{suffix}"))
    .fetch_one(&env.database)
    .await
    .expect("seed assignable plan");

    let mut promotion = env.database.begin().await.expect("begin owner promotion");
    let blocker_pid: i32 = chenxing_auth::sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *promotion)
        .await
        .expect("promotion backend pid");
    chenxing_auth::sqlx::query("UPDATE users SET role = 'owner' WHERE id = $1")
        .bind(target_id)
        .execute(&mut *promotion)
        .await
        .expect("stage owner promotion");

    let router = env.router.clone();
    let request = tokio::spawn(async move {
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/admin/users/{target_id}/plan"))
                    .header("cookie", cookie)
                    .header("x-csrf-token", csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"plan_id": plan_id, "expires_at": null}).to_string(),
                    ))
                    .expect("plan assignment request"),
            )
            .await
            .expect("plan assignment response")
    });

    wait_for_blocked_request(&env.database, blocker_pid).await;
    promotion.commit().await.expect("commit owner promotion");
    let response = request.await.expect("plan assignment task");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await["code"], "admin_forbidden");

    let state: (String, Option<i64>) =
        chenxing_auth::sqlx::query_as("SELECT role, plan_id FROM users WHERE id = $1")
            .bind(target_id)
            .fetch_one(&env.database)
            .await
            .expect("target state after denied plan assignment");
    assert_eq!(state, ("owner".to_owned(), None));
    assert_eq!(
        manage_roles_denial_count(&env.database, admin_id).await,
        1
    );
    let _ = std::fs::remove_dir_all(&env.key_directory);
}
