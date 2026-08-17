//! Issue #517: AdminWrite side effects recheck actor role/status/generation.
//!
//! Key rotation, TOTP reset, and privileged admin creation must lock the actor
//! inside the mutation transaction. A concurrent role demote, disable, or epoch
//! bump that commits after the handler's first authorize() must still reject the
//! write with zero side effects. `ADMIN_TOKEN` stays a system actor and succeeds.

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

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_support;

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
        "admin_write_actor_race",
        &database_url,
        10,
    )
    .await;
    let key_directory = oauth_support::isolated_key_directory("admin-write-actor-race");
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

async fn insert_totp(database: &chenxing_auth::sqlx::PgPool, user_id: i64) {
    chenxing_auth::sqlx::query(
        "INSERT INTO user_totp_factors (user_id, encrypted_secret, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(user_id)
    .bind([1_u8, 2, 3, 4].as_slice())
    .execute(database)
    .await
    .expect("insert TOTP");
}

async fn totp_exists(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> bool {
    chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_totp_factors WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(database)
    .await
    .expect("totp exists")
}

async fn username_exists(database: &chenxing_auth::sqlx::PgPool, username: &str) -> bool {
    chenxing_auth::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)")
        .bind(username)
        .fetch_one(database)
        .await
        .expect("username exists")
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

/// Wait until the request is blocked by the transaction that staged the actor change.
/// This is a real PostgreSQL barrier, not a scheduling sleep.
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
enum ActorMutation {
    Role,
    Status,
    Generation,
}

impl ActorMutation {
    const fn label(self) -> &'static str {
        match self {
            Self::Role => "role",
            Self::Status => "status",
            Self::Generation => "generation",
        }
    }

    const fn expected_status(self) -> StatusCode {
        match self {
            Self::Role => StatusCode::FORBIDDEN,
            Self::Status | Self::Generation => StatusCode::UNAUTHORIZED,
        }
    }

    const fn expected_code(self) -> &'static str {
        match self {
            Self::Role => "admin_forbidden",
            Self::Status | Self::Generation => "invalid_session",
        }
    }
}

#[derive(Clone, Copy)]
enum WriteTarget {
    KeyRotate,
    TotpReset,
    CreateAdmin,
}

impl WriteTarget {
    const fn label(self) -> &'static str {
        match self {
            Self::KeyRotate => "key_rotate",
            Self::TotpReset => "totp_reset",
            Self::CreateAdmin => "create_admin",
        }
    }
}

struct CaseState {
    target_id: i64,
    new_admin_username: String,
    kid_before: String,
}

fn write_request(
    target: WriteTarget,
    cookie: String,
    csrf: String,
    case: &CaseState,
) -> Request<Body> {
    match target {
        WriteTarget::KeyRotate => Request::builder()
            .method("POST")
            .uri("/api/v1/admin/keys/rotate")
            .header("cookie", cookie)
            .header("x-csrf-token", csrf)
            .body(Body::empty())
            .expect("key rotate request"),
        WriteTarget::TotpReset => Request::builder()
            .method("DELETE")
            .uri(format!(
                "/api/v1/admin/users/{}/auth-factors/totp",
                case.target_id
            ))
            .header("cookie", cookie)
            .header("x-csrf-token", csrf)
            .body(Body::empty())
            .expect("totp reset request"),
        WriteTarget::CreateAdmin => Request::builder()
            .method("POST")
            .uri("/api/v1/admin/admins")
            .header("cookie", cookie)
            .header("x-csrf-token", csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "username": case.new_admin_username,
                    "email": format!("{}@example.com", case.new_admin_username),
                    "password": "correct-horse-battery",
                    "role": "admin"
                })
                .to_string(),
            ))
            .expect("create admin request"),
    }
}

async fn assert_no_side_effect(env: &TestEnv, case: &CaseState, label: &str) {
    assert_eq!(
        env.state.keys.key_id(),
        case.kid_before,
        "{label}: signing kid must stay unchanged"
    );
    assert!(
        totp_exists(&env.database, case.target_id).await,
        "{label}: TOTP row must remain"
    );
    assert!(
        !username_exists(&env.database, &case.new_admin_username).await,
        "{label}: no new admin user"
    );
}

async fn stage_actor_change(
    database: &chenxing_auth::sqlx::PgPool,
    actor_id: i64,
    mutation: ActorMutation,
) -> chenxing_auth::sqlx::Transaction<'_, chenxing_auth::sqlx::Postgres> {
    let mut actor_change = database.begin().await.expect("begin actor change");
    match mutation {
        ActorMutation::Role => {
            chenxing_auth::sqlx::query("UPDATE users SET role = 'admin' WHERE id = $1")
                .bind(actor_id)
                .execute(&mut *actor_change)
                .await
                .expect("stage actor role downgrade");
        }
        ActorMutation::Status => {
            chenxing_auth::sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
                .bind(actor_id)
                .execute(&mut *actor_change)
                .await
                .expect("stage actor disable");
        }
        ActorMutation::Generation => {
            chenxing_auth::sqlx::query(
                "UPDATE users SET session_epoch = session_epoch + 1 WHERE id = $1",
            )
            .bind(actor_id)
            .execute(&mut *actor_change)
            .await
            .expect("stage actor credential rotation");
        }
    }
    actor_change
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actor_active_role_and_generation_are_rechecked_on_admin_write_side_effects() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    seed_user(&env.database, &format!("owner-{suffix}"), "owner").await;

    for target in [
        WriteTarget::KeyRotate,
        WriteTarget::TotpReset,
        WriteTarget::CreateAdmin,
    ] {
        for mutation in [
            ActorMutation::Role,
            ActorMutation::Status,
            ActorMutation::Generation,
        ] {
            let label = format!("{}-{}", target.label(), mutation.label());
            let actor_id = seed_user(
                &env.database,
                &format!("actor-{}-{suffix}", label.replace('_', "")),
                "owner",
            )
            .await;
            let target_id = seed_user(
                &env.database,
                &format!("tgt-{}-{suffix}", label.replace('_', "")),
                "user",
            )
            .await;
            insert_totp(&env.database, target_id).await;
            let new_admin_username = format!("nadm{}{suffix}", &label.replace('_', "")[..4]);
            let case = CaseState {
                target_id,
                new_admin_username,
                kid_before: env.state.keys.key_id(),
            };

            let mut session = Session::new(actor_id.to_string(), Duration::from_secs(3600))
                .expect("actor session");
            env.state
                .sessions
                .save(&mut session, Duration::from_secs(3600))
                .await
                .expect("save actor session");
            let cookie = oauth_support::session_cookie(&session);
            let csrf = session.csrf_token.clone();

            let mut actor_change = stage_actor_change(&env.database, actor_id, mutation).await;
            let blocker_pid: i32 = chenxing_auth::sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *actor_change)
                .await
                .expect("actor change backend pid");

            let router = env.router.clone();
            let request_body = write_request(target, cookie, csrf, &case);
            let request = tokio::spawn(async move {
                router
                    .oneshot(request_body)
                    .await
                    .expect("admin write response")
            });

            wait_for_actor_lock(&env.database, blocker_pid).await;
            actor_change.commit().await.expect("commit actor change");
            let response = request.await.expect("admin write request task");
            assert_eq!(response.status(), mutation.expected_status(), "{label}");
            assert_eq!(
                response_json(response).await["code"],
                mutation.expected_code(),
                "{label}"
            );
            assert_no_side_effect(&env, &case, &label).await;
        }
    }

    let _ = std::fs::remove_dir_all(&env.key_directory);
}

#[tokio::test]
async fn admin_token_still_succeeds_on_the_same_write_endpoints() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    seed_user(&env.database, &format!("owner-{suffix}"), "owner").await;
    let target_id = seed_user(&env.database, &format!("tgt-{suffix}"), "user").await;
    insert_totp(&env.database, target_id).await;
    let kid_before = env.state.keys.key_id();
    let new_admin_username = format!("tokadm{suffix}");

    let rotate = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/keys/rotate")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("token rotate request"),
        )
        .await
        .expect("token rotate response");
    assert_eq!(rotate.status(), StatusCode::OK);
    let rotate = response_json(rotate).await;
    assert_ne!(rotate["key_id"].as_str(), Some(kid_before.as_str()));

    let reset = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{target_id}/auth-factors/totp"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("token totp reset request"),
        )
        .await
        .expect("token totp reset response");
    assert_eq!(reset.status(), StatusCode::OK);
    assert!(!totp_exists(&env.database, target_id).await);

    let created = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/admins")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": new_admin_username,
                        "email": format!("{new_admin_username}@example.com"),
                        "password": "correct-horse-battery",
                        "role": "admin"
                    })
                    .to_string(),
                ))
                .expect("token create admin request"),
        )
        .await
        .expect("token create admin response");
    assert_eq!(created.status(), StatusCode::CREATED);
    assert!(username_exists(&env.database, &new_admin_username).await);

    let _ = std::fs::remove_dir_all(&env.key_directory);
}

#[tokio::test]
async fn pre_promotion_session_cannot_use_owner_only_writes() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    seed_user(&env.database, &format!("owner-{suffix}"), "owner").await;
    let actor_id = seed_user(&env.database, &format!("actor-{suffix}"), "admin").await;
    let target_id = seed_user(&env.database, &format!("tgt-{suffix}"), "user").await;
    insert_totp(&env.database, target_id).await;
    let new_admin_username = format!("promadm{suffix}");
    let case = CaseState {
        target_id,
        new_admin_username,
        kid_before: env.state.keys.key_id(),
    };

    let mut session =
        Session::new(actor_id.to_string(), Duration::from_secs(3600)).expect("admin session");
    env.state
        .sessions
        .save(&mut session, Duration::from_secs(3600))
        .await
        .expect("save admin session");
    let cookie = oauth_support::session_cookie(&session);
    let csrf = session.csrf_token.clone();

    let promote = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{actor_id}/role"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "owner"}).to_string()))
                .expect("promote request"),
        )
        .await
        .expect("promote response");
    assert_eq!(promote.status(), StatusCode::NO_CONTENT);

    for target in [
        WriteTarget::KeyRotate,
        WriteTarget::TotpReset,
        WriteTarget::CreateAdmin,
    ] {
        let response = env
            .router
            .clone()
            .oneshot(write_request(target, cookie.clone(), csrf.clone(), &case))
            .await
            .expect("pre-promotion session write");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{}",
            target.label()
        );
        assert_eq!(
            response_json(response).await["code"],
            "invalid_session",
            "{}",
            target.label()
        );
    }
    assert_no_side_effect(&env, &case, "pre-promotion").await;

    let _ = std::fs::remove_dir_all(&env.key_directory);
}
