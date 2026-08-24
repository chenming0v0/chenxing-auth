//! #460 回归测试：受控的 Passkey-only 恢复。
//!
//! Passkey-only 账号丢了全部认证器之后没有自助出口：登录要现有 Passkey，
//! 管理 Session 也要先登录。末位 Owner 会把自己锁死。本文件锁定：
//!
//! 1. 系统 `ADMIN_TOKEN` 不依赖 Session / Passkey / CSRF，能重置末位 Owner。
//! 2. 重置与撤销同事务：没有凭据可删时整体回滚，不推进 `session_epoch`。
//! 3. 成功重置删除全部凭据、推进 epoch、撤销 Session，旧 Cookie 立刻失效。
//! 4. 权限是 Owner 专属的 `manage_auth_factors`；Admin 被 403，缺 CSRF 被 400。
//! 5. 重置后末位 Owner 能用密码登录，并从已认证安全 API 重新绑定。

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    clock::SharedClock,
    config::Config,
    sessions::{cookies, domain::Session},
    state::AppState,
};
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{db_isolation, oauth_flow, totp_time};

const ADMIN_TOKEN: &str = "passkey-recovery-admin-token";
const PASSWORD: &str = "correct horse battery";

struct Harness {
    router: Router,
    state: AppState,
    database: chenxing_auth::sqlx::PgPool,
    key_directory: std::path::PathBuf,
}

impl Harness {
    async fn new() -> Self {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned()
        });
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        let database = db_isolation::isolated_pool("passkey_recovery", &database_url).await;
        let key_directory = oauth_flow::isolated_key_directory("passkey-recovery");
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
        let state = AppState::new_with_pool(config, database.clone())
            .await
            .expect("test state")
            .with_clock(SharedClock::fixed(totp_time::centered_now()));
        let router = api::router(state.clone());
        oauth_flow::ensure_owner_bootstrapped(
            &router,
            &database,
            "passkey_recovery",
            "passkey_recovery",
        )
        .await;
        Self {
            router,
            state,
            database,
            key_directory,
        }
    }

    fn cleanup(self) {
        let _ = std::fs::remove_dir_all(self.key_directory);
    }
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON response")
}

async fn last_owner(database: &chenxing_auth::sqlx::PgPool) -> (i64, String) {
    let (id, username): (i64, String) = chenxing_auth::sqlx::query_as(
        "SELECT id, username FROM users WHERE role = 'owner' ORDER BY id ASC LIMIT 1",
    )
    .fetch_one(database)
    .await
    .expect("last owner");
    (id, username)
}

async fn session_epoch(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("session epoch")
}

async fn passkey_count(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM user_passkeys WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("passkey count")
}

async fn insert_passkeys(database: &chenxing_auth::sqlx::PgPool, user_id: i64, count: usize) {
    for _ in 0..count {
        chenxing_auth::sqlx::query(
            "INSERT INTO user_passkeys
                (user_id, credential_id, credential, created_at, updated_at)
             VALUES ($1, $2, '{}'::jsonb, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(Uuid::new_v4().into_bytes().to_vec())
        .execute(database)
        .await
        .expect("insert passkey");
    }
}

async fn insert_totp(database: &chenxing_auth::sqlx::PgPool, user_id: i64) {
    chenxing_auth::sqlx::query(
        "INSERT INTO user_totp_factors
            (user_id, encrypted_secret, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(user_id)
    .bind([1_u8, 2, 3, 4].as_slice())
    .execute(database)
    .await
    .expect("insert TOTP");
}

async fn browser_session(state: &AppState, user_id: i64) -> (String, String) {
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("browser session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("save browser session");
    (
        format!(
            "{}={}; {}={}",
            cookies::session_cookie_name(false),
            session.token,
            cookies::csrf_cookie_name(false),
            session.csrf_token
        ),
        session.csrf_token,
    )
}

async fn create_user(router: &Router, role: &str) -> (i64, String) {
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("passkey-recovery-{role}-{suffix}");
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
                        "username": username,
                        "email": format!("{username}@example.com"),
                        "password": PASSWORD,
                        "role": role,
                    })
                    .to_string(),
                ))
                .expect("create user request"),
        )
        .await
        .expect("create user response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user_id = json_body(response).await["id"]
        .as_i64()
        .expect("created user id");
    (user_id, username)
}

async fn reset_with_token(router: &Router, user_id: i64) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/admin/users/{user_id}/auth-factors/passkey"
                ))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("system token reset request"),
        )
        .await
        .expect("system token reset response")
}

async fn get_me(router: &Router, cookie: &str) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("me request"),
        )
        .await
        .expect("me response")
}

fn pending_cookie(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().expect("cookie pair"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn cookie_value(cookie: &str, name: &str) -> String {
    cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix(&format!("{name}=")))
        .expect("cookie value")
        .to_owned()
}

/// 末位 Owner 丢失全部 Passkey 后，系统 Token 是唯一不形成闭环的恢复入口。
#[tokio::test]
async fn system_token_recovers_last_owner_without_existing_passkey_or_session() {
    let harness = Harness::new().await;
    let (owner_id, owner_username) = last_owner(&harness.database).await;
    insert_passkeys(&harness.database, owner_id, 2).await;
    let (owner_cookie, _) = browser_session(&harness.state, owner_id).await;
    assert_eq!(
        get_me(&harness.router, &owner_cookie).await.status(),
        StatusCode::OK,
        "pre-reset session must work so revocation is observable"
    );
    let epoch_before = session_epoch(&harness.database, owner_id).await;

    // 关键：不带 Session Cookie、不带 CSRF、不验 Passkey。
    let reset = reset_with_token(&harness.router, owner_id).await;
    assert_eq!(reset.status(), StatusCode::OK);
    let body = json_body(reset).await;
    assert_eq!(body["user_id"], owner_id);
    assert_eq!(body["removed"], 2);
    assert_eq!(body["credentials_revoked"], true);
    assert!(body.get("credential_id").is_none());
    assert!(body.get("credential").is_none());

    assert_eq!(passkey_count(&harness.database, owner_id).await, 0);
    assert_eq!(
        session_epoch(&harness.database, owner_id).await,
        epoch_before + 1
    );
    let revoked: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_sessions
         WHERE user_id = $1 AND revoked_at IS NOT NULL",
    )
    .bind(owner_id)
    .fetch_one(&harness.database)
    .await
    .expect("revoked session count");
    assert!(revoked >= 1, "reset must revoke the outstanding session");
    assert_eq!(
        get_me(&harness.router, &owner_cookie).await.status(),
        StatusCode::UNAUTHORIZED,
        "old session cookie must die with the advanced epoch"
    );

    let login = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "identifier": owner_username,
                        "password": PASSWORD,
                    })
                    .to_string(),
                ))
                .expect("owner password login"),
        )
        .await
        .expect("owner password login response");
    assert_eq!(login.status(), StatusCode::OK);
    let login_cookie = pending_cookie(&login);
    let csrf = cookie_value(&login_cookie, cookies::csrf_cookie_name(false));
    let login_body = json_body(login).await;
    assert!(login_body["expires_at"].as_str().is_some());

    let setup = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/security/totp/enrollment/start")
                .header("content-type", "application/json")
                .header("cookie", &login_cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from("{}"))
                .expect("totp setup request"),
        )
        .await
        .expect("totp setup response");
    assert_eq!(setup.status(), StatusCode::OK);
    let setup_body = json_body(setup).await;
    let totp = TOTP::from_url(setup_body["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    let previous = totp_time::previous_timestep(harness.state.clock.now());
    let confirm = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/security/totp/enrollment/confirm")
                .header("content-type", "application/json")
                .header("cookie", &login_cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from(
                    serde_json::json!({
                        "enrollment_id": setup_body["enrollment_id"],
                        "code": totp.generate(previous)
                    })
                    .to_string(),
                ))
                .expect("totp confirm request"),
        )
        .await
        .expect("totp confirm response");
    assert_eq!(
        confirm.status(),
        StatusCode::OK,
        "last owner must be able to re-bind a factor after recovery"
    );

    let (actor_type, metadata): (String, serde_json::Value) = chenxing_auth::sqlx::query_as(
        "SELECT actor_type, metadata FROM audit_events
         WHERE action = 'user_passkey_factor_reset' AND resource_id = $1
         ORDER BY id DESC LIMIT 1",
    )
    .bind(owner_id.to_string())
    .fetch_one(&harness.database)
    .await
    .expect("passkey reset audit");
    assert_eq!(actor_type, "system_token");
    assert_eq!(metadata["method"], "passkey");
    assert_eq!(metadata["removed"], 2);
    assert_eq!(metadata["credentials_revoked"], true);
    for sensitive_key in ["credential_id", "credential", "public_key", "counter"] {
        assert!(
            metadata.get(sensitive_key).is_none(),
            "audit metadata must not contain {sensitive_key}"
        );
    }

    harness.cleanup();
}

/// 没有 Passkey 可删时必须整体回滚：epoch 不动，现有 Session 继续有效。
#[tokio::test]
async fn missing_passkeys_roll_back_revocation() {
    let harness = Harness::new().await;
    let (user_id, _) = create_user(&harness.router, "user").await;
    let (cookie, _) = browser_session(&harness.state, user_id).await;
    let epoch_before = session_epoch(&harness.database, user_id).await;

    let reset = reset_with_token(&harness.router, user_id).await;
    assert_eq!(reset.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(reset).await["code"], "passkey_factor_not_found");
    assert_eq!(
        session_epoch(&harness.database, user_id).await,
        epoch_before
    );
    assert_eq!(
        get_me(&harness.router, &cookie).await.status(),
        StatusCode::OK,
        "failed reset must not kick the user offline"
    );

    let unknown = reset_with_token(&harness.router, 9_000_000_001).await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(unknown).await["code"], "user_not_found");

    harness.cleanup();
}

/// 权限与 CSRF：Admin 不得重置；Owner 浏览器写操作必须带齐三件套。
#[tokio::test]
async fn passkey_reset_requires_owner_or_system_token() {
    let harness = Harness::new().await;
    let (target_id, _) = create_user(&harness.router, "user").await;
    insert_passkeys(&harness.database, target_id, 1).await;
    insert_totp(&harness.database, target_id).await;
    let (admin_id, _) = create_user(&harness.router, "admin").await;
    let (admin_cookie, admin_csrf) = browser_session(&harness.state, admin_id).await;
    let (owner_id, _) = last_owner(&harness.database).await;
    let (owner_cookie, owner_csrf) = browser_session(&harness.state, owner_id).await;

    let denied = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/admin/users/{target_id}/auth-factors/passkey"
                ))
                .header("cookie", &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .body(Body::empty())
                .expect("admin reset request"),
        )
        .await
        .expect("admin reset response");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(denied).await["code"], "admin_forbidden");
    assert_eq!(passkey_count(&harness.database, target_id).await, 1);

    let without_csrf = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/admin/users/{target_id}/auth-factors/passkey"
                ))
                .header("cookie", &owner_cookie)
                .body(Body::empty())
                .expect("owner reset without CSRF"),
        )
        .await
        .expect("owner reset without CSRF response");
    assert_eq!(without_csrf.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(without_csrf).await["code"], "csrf_invalid");
    assert_eq!(passkey_count(&harness.database, target_id).await, 1);

    let allowed = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/admin/users/{target_id}/auth-factors/passkey"
                ))
                .header("cookie", &owner_cookie)
                .header("x-csrf-token", &owner_csrf)
                .body(Body::empty())
                .expect("owner reset request"),
        )
        .await
        .expect("owner reset response");
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(json_body(allowed).await["removed"], 1);
    assert_eq!(passkey_count(&harness.database, target_id).await, 0);
    let totp_still_there: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_totp_factors WHERE user_id = $1)",
    )
    .bind(target_id)
    .fetch_one(&harness.database)
    .await
    .expect("totp remains");
    assert!(
        totp_still_there,
        "passkey reset must not delete a remaining TOTP factor"
    );

    let (actor_type, actor_id): (String, Option<i64>) = chenxing_auth::sqlx::query_as(
        "SELECT actor_type, actor_user_id FROM audit_events
         WHERE action = 'user_passkey_factor_reset' AND resource_id = $1
         ORDER BY id DESC LIMIT 1",
    )
    .bind(target_id.to_string())
    .fetch_one(&harness.database)
    .await
    .expect("owner reset audit");
    assert_eq!(actor_type, "user");
    assert_eq!(actor_id, Some(owner_id));

    harness.cleanup();
}
