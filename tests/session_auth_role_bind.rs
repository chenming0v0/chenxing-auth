//! Issue #646: session authentication must bind role state in one consistent read.
//!
//! Role transitions revoke sessions and assign the new role atomically. The old
//! `current_user` path looked up the Cookie first, then loaded the user profile
//! in a second query. Those two unlocked reads can straddle the promotion
//! commit: session S is still live at the first read, and the second read sees
//! Owner. Permission checks then trust the new role and the revoked Cookie can
//! perform an Owner-only mutation.
//!
//! The relevant interleaving is therefore:
//! 1. start with ordinary-user session S
//! 2. commit a promotion that revokes S and grants Owner
//! 3. the role/permission load must fail closed (`invalid_session`) rather than
//!    inherit Owner

use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api, config::Config, sessions::domain::Session, state::AppState, users::domain::UserRole,
};
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
        "session_auth_role_bind",
        &database_url,
        10,
    )
    .await;
    let key_directory = oauth_support::isolated_key_directory("session-auth-role-bind");
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

async fn stored_role(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> String {
    chenxing_auth::sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("read user role")
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

fn owner_role_request(target_id: i64, cookie: String, csrf: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/users/{target_id}/role"))
        .header("cookie", cookie)
        .header("x-csrf-token", csrf)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"role": "admin"}).to_string()))
        .expect("owner-only role request")
}

async fn promote_to_owner(env: &TestEnv, user_id: i64) {
    let response = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/role"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "owner"}).to_string()))
                .expect("promotion request"),
        )
        .await
        .expect("promotion response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(stored_role(&env.database, user_id).await, "owner");
}

#[tokio::test]
async fn revoked_pre_promotion_session_cannot_inherit_owner_role() {
    let env = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    seed_user(&env.database, &format!("seed-owner-{suffix}"), "owner").await;
    let user_id = seed_user(&env.database, &format!("ordinary-{suffix}"), "user").await;
    let target_id = seed_user(&env.database, &format!("target-{suffix}"), "user").await;

    let session = save_session(&env, user_id).await;
    let token = session.token.clone();
    let cookie = oauth_support::session_cookie(&session);
    let csrf = session.csrf_token.clone();

    let bound_before = env
        .state
        .sessions
        .find_authenticated(&token)
        .await
        .expect("bound lookup before promotion")
        .expect("ordinary-user session must authenticate");
    assert_eq!(bound_before.role, UserRole::User);
    assert_eq!(bound_before.session.id, session.id);

    let before = env
        .router
        .clone()
        .oneshot(owner_role_request(target_id, cookie.clone(), csrf.clone()))
        .await
        .expect("pre-promotion owner mutation");
    assert_eq!(before.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(before).await["code"], "admin_forbidden");
    assert_eq!(stored_role(&env.database, target_id).await, "user");

    // Historical two-read window: unlocked session lookup, then a later profile
    // read. The promotion commit sits between them.
    let live_before = env
        .state
        .sessions
        .find(&token)
        .await
        .expect("session lookup before promotion");
    assert!(
        live_before.is_some(),
        "the request begins with a still-valid ordinary-user session"
    );

    promote_to_owner(&env, user_id).await;

    let profile_after = env
        .state
        .users
        .find_profile(user_id)
        .await
        .expect("profile lookup after promotion")
        .expect("promoted user still exists");
    assert_eq!(
        profile_after.role,
        UserRole::Owner,
        "a late role read sees the new Owner grant"
    );
    assert!(
        env.state
            .sessions
            .find(&token)
            .await
            .expect("session lookup after promotion")
            .is_none(),
        "the pre-promotion Cookie must be revoked with the role change"
    );
    assert!(
        env.state
            .sessions
            .find_authenticated(&token)
            .await
            .expect("bound lookup after promotion")
            .is_none(),
        "the bound read must not return Owner for a revoked pre-promotion session"
    );

    let after = env
        .router
        .clone()
        .oneshot(owner_role_request(target_id, cookie, csrf))
        .await
        .expect("post-promotion owner mutation");
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response_json(after).await["code"], "invalid_session");
    assert_eq!(
        stored_role(&env.database, target_id).await,
        "user",
        "the revoked Cookie must not complete an Owner-only mutation"
    );

    let owner_session = save_session(&env, user_id).await;
    let recovered = env
        .router
        .clone()
        .oneshot(owner_role_request(
            target_id,
            oauth_support::session_cookie(&owner_session),
            owner_session.csrf_token.clone(),
        ))
        .await
        .expect("fresh owner session mutation");
    assert_eq!(
        recovered.status(),
        StatusCode::NO_CONTENT,
        "a newly issued Owner session must still be able to mutate"
    );
    assert_eq!(stored_role(&env.database, target_id).await, "admin");

    let _ = std::fs::remove_dir_all(&env.key_directory);
}
