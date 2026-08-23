//! Issue #647: management writes must bind the exact authenticated session row.
//!
//! Single-session revocation sets `user_sessions.revoked_at` without advancing
//! `users.session_epoch`. The old actor check only compared role, status, and
//! generation, so a Cookie whose row was already revoked could still complete a
//! guarded mutation. The relevant interleaving is: authenticate with S, enter
//! the write transaction far enough to wait on the actor user row, revoke S
//! without an epoch bump, then let the mutation continue.

use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, sessions::domain::Session, state::AppState};
use tokio::time::{sleep, timeout};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{db_isolation, oauth_flow as oauth_support};

const ADMIN_TOKEN: &str = "flow-admin-token";

struct TestEnv {
    state: AppState,
    router: Router,
    database: chenxing_auth::sqlx::PgPool,
    key_directory: std::path::PathBuf,
}

async fn setup() -> TestEnv {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool_with_max_connections(
        "admin_management_session_bind",
        &database_url,
        10,
    )
    .await;
    let key_directory = oauth_support::isolated_key_directory("admin-management-session-bind");
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
    let mut state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state");
    oauth_support::qps_window::override_qps_window(&mut state);
    TestEnv {
        router: api::router(state.clone()),
        state,
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

async fn current_epoch(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("read session epoch")
}

async fn user_status(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> String {
    chenxing_auth::sqlx::query_scalar("SELECT status FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("read user status")
}

async fn save_session(env: &TestEnv, user_id: i64) -> Session {
    let mut session =
        Session::new(user_id.to_string(), Duration::from_secs(3600)).expect("session");
    env.state
        .sessions
        .save(&mut session, Duration::from_secs(3600))
        .await
        .expect("save session");
    session
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn wait_for_actor_lock(database: &chenxing_auth::sqlx::PgPool, blocker_pid: i32) {
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
    .expect("admin write never reached the actor row lock");
}

fn disable_request(target_id: i64, cookie: String, csrf: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/users/{target_id}/disabled"))
        .header("cookie", cookie)
        .header("x-csrf-token", csrf)
        .body(Body::empty())
        .expect("target status request")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_session_cannot_complete_a_guarded_mutation_without_epoch_bump() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    seed_user(&env.database, &format!("owner-{suffix}"), "owner").await;
    let actor_id = seed_user(&env.database, &format!("actor-{suffix}"), "admin").await;
    let target_id = seed_user(&env.database, &format!("target-{suffix}"), "user").await;

    let revoked = save_session(&env, actor_id).await;
    let live = save_session(&env, actor_id).await;
    assert_ne!(
        revoked.id, live.id,
        "the regression needs two distinct session rows"
    );
    let epoch_before = current_epoch(&env.database, actor_id).await;
    assert_eq!(revoked.credential_generation(), Some(epoch_before));
    assert_eq!(live.credential_generation(), Some(epoch_before));

    let cookie = oauth_support::session_cookie(&revoked);
    let csrf = revoked.csrf_token.clone();
    let revoked_token = revoked.token.clone();

    let mut actor_lock = env.database.begin().await.expect("begin actor lock");
    let blocker_pid: i32 = chenxing_auth::sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *actor_lock)
        .await
        .expect("actor lock backend pid");
    chenxing_auth::sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(actor_id)
        .fetch_one(&mut *actor_lock)
        .await
        .expect("lock actor user row");

    let router = env.router.clone();
    let request = tokio::spawn(async move {
        router
            .oneshot(disable_request(target_id, cookie, csrf))
            .await
            .expect("target write response")
    });

    wait_for_actor_lock(&env.database, blocker_pid).await;
    env.state
        .sessions
        .revoke(&revoked_token)
        .await
        .expect("revoke authenticated session without advancing user epoch");
    assert_eq!(
        current_epoch(&env.database, actor_id).await,
        epoch_before,
        "single-session revoke must not bump users.session_epoch"
    );
    assert!(
        env.state
            .sessions
            .find(&revoked_token)
            .await
            .expect("look up revoked session")
            .is_none()
    );
    assert!(
        env.state
            .sessions
            .find(&live.token)
            .await
            .expect("look up sibling session")
            .is_some(),
        "the other session for the same user must remain live"
    );

    actor_lock.commit().await.expect("release actor row lock");
    let response = request.await.expect("target write request task");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response_json(response).await["code"], "invalid_session");
    assert_eq!(user_status(&env.database, target_id).await, "active");

    let live_response = env
        .router
        .clone()
        .oneshot(disable_request(
            target_id,
            oauth_support::session_cookie(&live),
            live.csrf_token.clone(),
        ))
        .await
        .expect("sibling session write response");
    assert_eq!(
        live_response.status(),
        StatusCode::NO_CONTENT,
        "a still-valid sibling session must keep working without an epoch bump"
    );
    assert_eq!(user_status(&env.database, target_id).await, "disabled");
    assert_eq!(current_epoch(&env.database, actor_id).await, epoch_before);

    let _ = std::fs::remove_dir_all(&env.key_directory);
}
