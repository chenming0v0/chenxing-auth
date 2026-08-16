//! Issue #493: role changes and administrator writes share one credential generation boundary.
//!
//! The first regression walks every role transition and proves that each committed change advances
//! `session_epoch`, revokes the old browser Session, and makes an outstanding Refresh Token
//! unredeemable. The second regression uses PostgreSQL row-lock barriers to place an actor change
//! after the handler's initial authorization but before the target write transaction can continue.

use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chenxing_auth::{
    api, config::Config, oauth::code::AuthorizationCode, sessions::domain::Session, state::AppState,
};
use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_support;

const ADMIN_TOKEN: &str = "flow-admin-token";
const REDIRECT_URI: &str = "https://disabled.example/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

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
    // The barrier regression needs one connection for the blocker, one for the request, and one
    // for the lock-wait probe. OAuth setup and assertions may overlap with those operations.
    let database = db_isolation::isolated_pool_with_max_connections(
        "admin_role_generation",
        &database_url,
        10,
    )
    .await;
    let key_directory = oauth_support::isolated_key_directory("admin-role-generation");
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

async fn stored_role(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> String {
    chenxing_auth::sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("read user role")
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn save_consent(database: &chenxing_auth::sqlx::PgPool, user_id: i64, client_id: &str) {
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE
         SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(client_id)
    .bind(serde_json::json!(["openid"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(database)
    .await
    .expect("save user consent");
}

async fn issue_refresh_token(
    env: &TestEnv,
    user_id: i64,
    client_id: &str,
    client_secret: &str,
    session_token: &str,
) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let code = AuthorizationCode::new_with_nonce(
        client_id.to_owned(),
        REDIRECT_URI.to_owned(),
        user_id.to_string(),
        vec!["openid".to_owned()],
        challenge,
        Some("issue-493-nonce".to_owned()),
        // #508：缺少会话绑定的授权码在 Token 端点 fail-closed，必须绑定真实
        // 浏览器会话才能走通兑换路径。
        Some(session_token.to_owned()),
    );
    env.state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let response = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fdisabled.example%2Fcallback&code_verifier={VERIFIER}",
                    code.value
                )))
                .expect("authorization-code exchange request"),
        )
        .await
        .expect("authorization-code exchange response");
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await["refresh_token"]
        .as_str()
        .expect("issued refresh token")
        .to_owned()
}

async fn change_role(env: &TestEnv, user_id: i64, role: &str) {
    let response = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/role"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": role}).to_string()))
                .expect("role update request"),
        )
        .await
        .expect("role update response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "role={role}");
}

async fn assert_refresh_rejected(
    env: &TestEnv,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) {
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let response = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh_token}"
                )))
                .expect("refresh-token exchange request"),
        )
        .await
        .expect("refresh-token exchange response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await["error"].as_str(),
        Some("invalid_grant")
    );
    assert!(
        env.state
            .refresh_tokens
            .find(refresh_token)
            .await
            .expect("find generation-rejected refresh token")
            .is_some(),
        "generation rejection must happen before refresh-token consumption"
    );
}

#[tokio::test]
async fn every_role_change_rotates_generation_and_invalidates_existing_credentials() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    oauth_support::ensure_owner_bootstrapped(
        &env.router,
        &env.database,
        "admin_role_generation",
        &suffix,
    )
    .await;
    let (user_id, _, _, _) = oauth_support::register_test_user(&env.router, &suffix).await;
    let (client_id, client_secret) =
        oauth_support::create_test_client(&env.router, ADMIN_TOKEN).await;
    save_consent(&env.database, user_id, &client_id).await;

    for next_role in ["admin", "owner", "admin", "user"] {
        let epoch_before = current_epoch(&env.database, user_id).await;
        let mut session =
            Session::new(user_id.to_string(), Duration::from_secs(3600)).expect("session");
        env.state
            .sessions
            .save(&mut session, Duration::from_secs(3600))
            .await
            .expect("save browser session");
        assert_eq!(session.credential_generation(), Some(epoch_before));
        let session_token = session.token.clone();
        let refresh_token =
            issue_refresh_token(&env, user_id, &client_id, &client_secret, &session_token).await;

        change_role(&env, user_id, next_role).await;

        assert_eq!(stored_role(&env.database, user_id).await, next_role);
        assert_eq!(
            current_epoch(&env.database, user_id).await,
            epoch_before + 1,
            "{next_role} transition must advance the shared credential generation"
        );
        assert!(
            env.state
                .sessions
                .find(&session_token)
                .await
                .expect("look up revoked browser session")
                .is_none(),
            "the pre-change browser Session must be revoked for role={next_role}"
        );
        assert_refresh_rejected(&env, &client_id, &client_secret, &refresh_token).await;
    }

    let _ = std::fs::remove_dir_all(&env.key_directory);
}

/// Wait until the request is blocked by the transaction that staged the actor change. This is a
/// real PostgreSQL barrier, not a scheduling sleep: the old implementation never locks the actor
/// inside the target write transaction, so it cannot reach this state.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actor_active_role_and_generation_are_rechecked_inside_the_target_transaction() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    seed_user(&env.database, &format!("owner-{suffix}"), "owner").await;

    for mutation in [
        ActorMutation::Role,
        ActorMutation::Status,
        ActorMutation::Generation,
    ] {
        let label = mutation.label();
        let actor_role = if matches!(mutation, ActorMutation::Role) {
            "owner"
        } else {
            "admin"
        };
        let actor_id = seed_user(
            &env.database,
            &format!("actor-{label}-{suffix}"),
            actor_role,
        )
        .await;
        let target_id = seed_user(&env.database, &format!("target-{label}-{suffix}"), "user").await;
        let mut session =
            Session::new(actor_id.to_string(), Duration::from_secs(3600)).expect("actor session");
        env.state
            .sessions
            .save(&mut session, Duration::from_secs(3600))
            .await
            .expect("save actor session");
        let cookie = oauth_support::session_cookie(&session);
        let csrf = session.csrf_token.clone();

        let mut actor_change = env.database.begin().await.expect("begin actor change");
        let blocker_pid: i32 = chenxing_auth::sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *actor_change)
            .await
            .expect("actor change backend pid");
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

        let router = env.router.clone();
        let request = tokio::spawn(async move {
            let request = match mutation {
                ActorMutation::Role => Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/admin/users/{target_id}/role"))
                    .header("cookie", cookie)
                    .header("x-csrf-token", csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({"role": "owner"}).to_string()))
                    .expect("target role request"),
                ActorMutation::Status | ActorMutation::Generation => Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/admin/users/{target_id}/disabled"))
                    .header("cookie", cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .expect("target status request"),
            };
            router
                .oneshot(request)
                .await
                .expect("target write response")
        });

        wait_for_actor_lock(&env.database, blocker_pid).await;
        actor_change.commit().await.expect("commit actor change");
        let response = request.await.expect("target write request task");
        assert_eq!(response.status(), mutation.expected_status(), "{label}");
        assert_eq!(
            response_json(response).await["code"],
            mutation.expected_code(),
            "{label}"
        );
        let target_state: (String, String) =
            chenxing_auth::sqlx::query_as("SELECT role, status FROM users WHERE id = $1")
                .bind(target_id)
                .fetch_one(&env.database)
                .await
                .expect("target state after rejected write");
        assert_eq!(
            target_state,
            ("user".to_owned(), "active".to_owned()),
            "{label}"
        );
    }

    let _ = std::fs::remove_dir_all(&env.key_directory);
}
