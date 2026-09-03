//! Issue #694: management writes recheck absolute and idle Session expiry after lock waits.
//!
//! Browser authorization and CSRF validation happen before the mutation transaction. These
//! barriers prove that a request which passed that entry boundary cannot commit after its exact
//! Session crosses either deadline while waiting for the actor row. A live sibling Session for
//! the same Admin remains usable, and mutation/audit effects stay atomic.

use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    audit::{AuditEvent, AuditService},
    config::Config,
    sessions::domain::Session,
    state::AppState,
};
use tokio::time::{sleep, timeout};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{db_isolation, oauth_flow as oauth_support};

const ADMIN_TOKEN: &str = "flow-admin-token";
const DENIED_ACTION: &str = "admin_authorization_denied";
const MUTATION_ACTION: &str = "user_disabled";

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
        "admin_management_session_expiry",
        &database_url,
        10,
    )
    .await;
    let key_directory = oauth_support::isolated_key_directory("admin-management-session-expiry");
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

#[derive(Clone, Copy)]
enum ExpiryBoundary {
    Absolute,
    Idle,
}

impl ExpiryBoundary {
    const fn label(self) -> &'static str {
        match self {
            Self::Absolute => "absolute",
            Self::Idle => "idle",
        }
    }

    async fn arm(self, database: &chenxing_auth::sqlx::PgPool, session_id: i64) {
        let sql = match self {
            Self::Absolute => {
                "UPDATE user_sessions
                 SET expires_at = statement_timestamp() + INTERVAL '250 milliseconds'
                 WHERE id = $1"
            }
            Self::Idle => {
                "UPDATE user_sessions
                 SET idle_timeout_seconds = 1, last_seen_at = statement_timestamp()
                 WHERE id = $1"
            }
        };
        let affected = chenxing_auth::sqlx::query(sql)
            .bind(session_id)
            .execute(database)
            .await
            .expect("arm session expiry boundary")
            .rows_affected();
        assert_eq!(affected, 1, "session row must exist");
    }

    async fn wait_until_expired(self, database: &chenxing_auth::sqlx::PgPool, session_id: i64) {
        timeout(Duration::from_secs(5), async {
            loop {
                let expired: bool = match self {
                    Self::Absolute => {
                        chenxing_auth::sqlx::query_scalar(
                            "SELECT expires_at <= statement_timestamp()
                         FROM user_sessions
                         WHERE id = $1",
                        )
                        .bind(session_id)
                        .fetch_one(database)
                        .await
                    }
                    Self::Idle => {
                        chenxing_auth::sqlx::query_scalar(
                            "SELECT last_seen_at <= statement_timestamp()
                            - MAKE_INTERVAL(secs => idle_timeout_seconds)
                         FROM user_sessions
                         WHERE id = $1",
                        )
                        .bind(session_id)
                        .fetch_one(database)
                        .await
                    }
                }
                .expect("inspect session deadline");
                if expired {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("session deadline did not pass");
    }
}

fn disable_request(target_id: i64, session: &Session) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/users/{target_id}/disabled"))
        .header("cookie", oauth_support::session_cookie(session))
        .header("x-csrf-token", &session.csrf_token)
        .body(Body::empty())
        .expect("target status request")
}

async fn user_status(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> String {
    chenxing_auth::sqlx::query_scalar("SELECT status FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("read user status")
}

async fn audit_events(database: &chenxing_auth::sqlx::PgPool, action: &str) -> Vec<AuditEvent> {
    AuditService::new(database.clone())
        .query(Some(action), None, 100, 0)
        .await
        .expect("query audit events")
        .0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn management_writes_recheck_absolute_and_idle_expiry_after_actor_lock_waits() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    seed_user(&env.database, &format!("owner-{suffix}"), "owner").await;

    for boundary in [ExpiryBoundary::Absolute, ExpiryBoundary::Idle] {
        let label = boundary.label();
        let actor_id = seed_user(&env.database, &format!("actor-{label}-{suffix}"), "admin").await;
        let target_id = seed_user(&env.database, &format!("target-{label}-{suffix}"), "user").await;
        let expiring = save_session(&env, actor_id).await;
        let sibling = save_session(&env, actor_id).await;
        assert_ne!(expiring.id, sibling.id);

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
        let request = disable_request(target_id, &expiring);
        let pending = tokio::spawn(async move {
            router
                .oneshot(request)
                .await
                .expect("target write response")
        });

        // Reaching this lock proves the exact Cookie and matching CSRF triple already passed
        // the HTTP entry checks and the transaction began before the deadline crossed.
        wait_for_actor_lock(&env.database, blocker_pid).await;
        boundary.arm(&env.database, expiring.id).await;
        boundary
            .wait_until_expired(&env.database, expiring.id)
            .await;
        actor_lock.commit().await.expect("release actor row lock");

        let response = pending.await.expect("target write request task");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{label}");
        assert_eq!(response_json(response).await["code"], "invalid_session");
        assert_eq!(user_status(&env.database, target_id).await, "active");

        let target_id_text = target_id.to_string();
        let actor_id_text = actor_id.to_string();
        let mutations = audit_events(&env.database, MUTATION_ACTION).await;
        assert!(
            mutations
                .iter()
                .all(|event| event.resource_id.as_deref() != Some(target_id_text.as_str())),
            "{label}: rejected write must not commit its success audit"
        );
        let denials = audit_events(&env.database, DENIED_ACTION).await;
        let denial = denials
            .iter()
            .find(|event| event.actor_id.as_deref() == Some(actor_id_text.as_str()))
            .expect("expired management Session denial audit");
        assert_eq!(denial.resource_id.as_deref(), Some("ManageUsers"));
        assert_eq!(denial.metadata["reason"], "actor_session_changed");
        let serialized = serde_json::to_string(denial).expect("serialize denial audit");
        assert!(!serialized.contains(&expiring.token));
        assert!(!serialized.contains(&expiring.csrf_token));

        assert!(
            env.state
                .sessions
                .find(&sibling.token)
                .await
                .expect("look up sibling session")
                .is_some(),
            "{label}: expiry must stay bound to the exact Session row"
        );
        let live_response = env
            .router
            .clone()
            .oneshot(disable_request(target_id, &sibling))
            .await
            .expect("sibling Session write response");
        assert_eq!(live_response.status(), StatusCode::NO_CONTENT, "{label}");
        assert_eq!(user_status(&env.database, target_id).await, "disabled");
        assert!(
            audit_events(&env.database, MUTATION_ACTION)
                .await
                .iter()
                .any(|event| event.resource_id.as_deref() == Some(target_id_text.as_str())),
            "{label}: successful sibling write and audit must commit together"
        );
    }

    let _ = std::fs::remove_dir_all(&env.key_directory);
}
