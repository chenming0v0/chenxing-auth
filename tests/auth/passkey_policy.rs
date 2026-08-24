use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    auth_factors::crypto::encrypt_totp_secret_with_ring,
    config::{AuthEncryptionKey, AuthEncryptionKeyRing, Config},
    settings::{IssuerRuntime, issuer},
    sqlx,
    state::AppState,
};
use serde_json::Value;
use std::time::Duration;
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{db_isolation, oauth_flow};

const PASSWORD: &str = "correct horse battery";

fn current_key_ring() -> AuthEncryptionKeyRing {
    AuthEncryptionKeyRing::single(AuthEncryptionKey::new([0_u8; 32]))
}

fn retired_key_ring() -> AuthEncryptionKeyRing {
    AuthEncryptionKeyRing::from_entries(
        "retired".to_owned(),
        vec![("retired".to_owned(), AuthEncryptionKey::new([1_u8; 32]))],
    )
    .expect("retired test key ring")
}

async fn setup() -> (Router, sqlx::PgPool, std::path::PathBuf) {
    setup_with_derived_webauthn(false).await
}

async fn setup_with_derived_webauthn(
    derive_webauthn_from_issuer: bool,
) -> (Router, sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database =
        db_isolation::isolated_pool_with_max_connections("passkey_policy", &database_url, 6).await;
    set_passkey_setting(&database, true).await;

    let key_directory =
        std::env::temp_dir().join(format!("chenxing-passkey-policy-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "passkey-policy-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    config.auth_encryption_keys = current_key_ring();
    if derive_webauthn_from_issuer {
        config.webauthn_rp_id_explicit = false;
        config.webauthn_origin_explicit = false;
    }
    let router = api::router(
        AppState::new_with_pool(config, database.clone())
            .await
            .expect("state"),
    );
    oauth_flow::ensure_owner_bootstrapped(&router, &database, "passkey_policy", "passkey_policy")
        .await;
    (router, database, key_directory)
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON response")
}

async fn request(
    router: &Router,
    method: &str,
    uri: &str,
    body: Value,
    authorization: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(authorization) = authorization {
        builder = builder.header("authorization", authorization);
    }
    router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).expect("request"))
        .await
        .expect("response")
}

async fn request_with_session(
    router: &Router,
    method: &str,
    uri: &str,
    body: Value,
    cookie: &str,
    csrf: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response")
}

fn cookie_header(response: &axum::response::Response) -> String {
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

async fn create_user(router: &Router, database: &sqlx::PgPool) -> (i64, String) {
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("passkey-policy-{suffix}");
    let email = format!("{username}@example.com");
    let response = request(
        router,
        "POST",
        "/api/v1/admin/users",
        serde_json::json!({
            "username": username,
            "email": email,
            "password": PASSWORD
        }),
        Some("Bearer passkey-policy-token"),
    )
    .await;
    let status = response.status();
    let body = json(response).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "user creation response: {body}"
    );
    let user_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(database)
        .await
        .expect("user id");
    (user_id, username)
}

async fn insert_passkey(database: &sqlx::PgPool, user_id: i64) {
    sqlx::query(
        "INSERT INTO user_passkeys
            (user_id, credential_id, credential, created_at, updated_at)
         VALUES ($1, $2, '{}'::jsonb, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(Uuid::new_v4().into_bytes().to_vec())
    .execute(database)
    .await
    .expect("passkey factor");
}

async fn insert_totp(database: &sqlx::PgPool, user_id: i64) {
    let encrypted_secret = encrypt_totp_secret_with_ring(&current_key_ring(), b"JBSWY3DPEHPK3PXP")
        .expect("encrypt test TOTP secret");
    insert_totp_ciphertext(database, user_id, &encrypted_secret).await;
}

async fn insert_totp_ciphertext(database: &sqlx::PgPool, user_id: i64, ciphertext: &[u8]) {
    sqlx::query(
        "INSERT INTO user_totp_factors
            (user_id, encrypted_secret, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(ciphertext)
    .execute(database)
    .await
    .expect("TOTP factor");
}

async fn set_passkey_setting(database: &sqlx::PgPool, enabled: bool) {
    let setting = serde_json::json!({
        "enabled": enabled,
        "rp_name": "Passkey policy tests",
        "rp_id": "localhost",
        "user_verification": "preferred",
        "authenticator_attachment": "any",
        "allow_insecure_origin": true,
        "allowed_origins": ["http://localhost:3000"]
    });
    sqlx::query(
        "INSERT INTO app_settings (setting_key, setting_value, updated_at)
         VALUES ('passkey', $1, NOW())
         ON CONFLICT (setting_key) DO UPDATE
         SET setting_value = EXCLUDED.setting_value, updated_at = EXCLUDED.updated_at",
    )
    .bind(setting.to_string())
    .execute(database)
    .await
    .expect("Passkey setting");
}

async fn login(router: &Router, username: &str) -> Value {
    let response = request(
        router,
        "POST",
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": PASSWORD}),
        None,
    )
    .await;
    assert!(matches!(
        response.status(),
        StatusCode::OK | StatusCode::ACCEPTED
    ));
    json(response).await
}

async fn login_with_cookie(router: &Router, username: &str) -> (Value, String) {
    let response = request(
        router,
        "POST",
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": PASSWORD}),
        None,
    )
    .await;
    let cookie = cookie_header(&response);
    let body = json(response).await;
    (body, cookie)
}

async fn update_passkey_setting(router: &Router, enabled: bool) -> axum::response::Response {
    request(
        router,
        "PUT",
        "/api/v1/admin/settings/passkey",
        serde_json::json!({
            "enabled": enabled,
            "rp_name": "Passkey policy tests",
            "rp_id": "localhost",
            "user_verification": "preferred",
            "authenticator_attachment": "any",
            "allow_insecure_origin": true,
            "allowed_origins": ["http://localhost:3000"]
        }),
        Some("Bearer passkey-policy-token"),
    )
    .await
}

#[tokio::test]
async fn passkey_policy_does_not_turn_passkey_into_password_mfa() {
    let (router, database, key_directory) = setup().await;
    let (passkey_user, passkey_username) = create_user(&router, &database).await;
    let (totp_user, totp_username) = create_user(&router, &database).await;
    let (mixed_user, mixed_username) = create_user(&router, &database).await;
    let (empty_user, empty_username) = create_user(&router, &database).await;
    insert_passkey(&database, passkey_user).await;
    insert_totp(&database, totp_user).await;
    insert_passkey(&database, mixed_user).await;
    insert_totp(&database, mixed_user).await;

    assert!(
        login(&router, &passkey_username).await["expires_at"]
            .as_str()
            .is_some()
    );
    assert_eq!(
        login(&router, &totp_username).await["methods"],
        serde_json::json!(["totp"])
    );
    assert_eq!(
        login(&router, &mixed_username).await["methods"],
        serde_json::json!(["totp"])
    );
    assert!(
        login(&router, &empty_username).await["expires_at"]
            .as_str()
            .is_some()
    );

    let response = update_passkey_setting(&router, false).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "passkey_disable_blocked");

    insert_totp(&database, passkey_user).await;
    let response = update_passkey_setting(&router, false).await;
    assert_eq!(response.status(), StatusCode::OK);
    sqlx::query("DELETE FROM user_totp_factors WHERE user_id = $1")
        .bind(passkey_user)
        .execute(&database)
        .await
        .expect("remove recovery factor");

    let (passkey_login, session_cookie) = login_with_cookie(&router, &passkey_username).await;
    assert!(passkey_login["expires_at"].as_str().is_some());
    assert!(passkey_login.get("status").is_none());
    let recovery_audit: Option<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events
         WHERE actor_user_id = $1 AND action = 'passkey_recovery_required'
         ORDER BY id DESC LIMIT 1",
    )
    .bind(passkey_user)
    .fetch_optional(&database)
    .await
    .expect("recovery audit event");
    assert_eq!(recovery_audit.as_deref(), Some("passkey_recovery_required"));
    let csrf = cookie_value(&session_cookie, "chenxing_csrf");
    let setup_response = request_with_session(
        &router,
        "POST",
        "/api/v1/auth/security/totp/enrollment/start",
        serde_json::json!({}),
        &session_cookie,
        &csrf,
    )
    .await;
    assert_eq!(setup_response.status(), StatusCode::OK);
    let setup = json(setup_response).await;
    let totp =
        TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP setup");
    let response = request_with_session(
        &router,
        "POST",
        "/api/v1/auth/security/totp/enrollment/confirm",
        serde_json::json!({
            "enrollment_id": setup["enrollment_id"],
            "code": totp.generate_current().expect("TOTP code")
        }),
        &session_cookie,
        &csrf,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    sqlx::query("DELETE FROM user_totp_factors WHERE user_id = $1")
        .bind(passkey_user)
        .execute(&database)
        .await
        .expect("remove recovery factor after confirmation");

    assert_eq!(
        login(&router, &totp_username).await["methods"],
        serde_json::json!(["totp"])
    );
    assert_eq!(
        login(&router, &mixed_username).await["methods"],
        serde_json::json!(["totp"])
    );
    assert!(
        login(&router, &empty_username).await["expires_at"]
            .as_str()
            .is_some()
    );

    let response = update_passkey_setting(&router, true).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        login(&router, &passkey_username).await["expires_at"]
            .as_str()
            .is_some()
    );
    assert_eq!(
        login(&router, &totp_username).await["methods"],
        serde_json::json!(["totp"])
    );
    assert_eq!(
        login(&router, &mixed_username).await["methods"],
        serde_json::json!(["totp"])
    );
    assert!(
        login(&router, &empty_username).await["expires_at"]
            .as_str()
            .is_some()
    );

    let user_ids = vec![passkey_user, totp_user, mixed_user, empty_user];
    sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&user_ids)
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn passkey_disable_rejects_unavailable_totp_ciphertext() {
    let (router, database, key_directory) = setup().await;
    let (user_id, _) = create_user(&router, &database).await;
    insert_passkey(&database, user_id).await;
    insert_totp_ciphertext(&database, user_id, &[1, 2, 3, 4]).await;

    let response = update_passkey_setting(&router, false).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "passkey_disable_blocked");
    let enabled: bool = sqlx::query_scalar(
        "SELECT (setting_value::jsonb ->> 'enabled')::boolean
         FROM app_settings WHERE setting_key = 'passkey'",
    )
    .fetch_one(&database)
    .await
    .expect("passkey setting");
    assert!(enabled);

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn passkey_disable_rejects_totp_encrypted_by_retired_key() {
    let (router, database, key_directory) = setup().await;
    let (user_id, _) = create_user(&router, &database).await;
    insert_passkey(&database, user_id).await;
    let encrypted_secret = encrypt_totp_secret_with_ring(&retired_key_ring(), b"JBSWY3DPEHPK3PXP")
        .expect("encrypt retired-key TOTP secret");
    insert_totp_ciphertext(&database, user_id, &encrypted_secret).await;

    let response = update_passkey_setting(&router, false).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = json(response).await;
    assert_eq!(body["code"], "passkey_disable_blocked");
    assert!(!body.to_string().contains("retired"));

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passkey_disable_rechecks_after_a_registration_commits_under_policy_lock() {
    let (router, database, key_directory) = setup().await;
    let (user_id, _) = create_user(&router, &database).await;
    let mut gate = database.begin().await.expect("policy gate transaction");
    sqlx::query("SELECT pg_advisory_xact_lock(0, 7341931)")
        .execute(&mut *gate)
        .await
        .expect("hold Passkey policy lock");
    sqlx::query(
        "INSERT INTO user_passkeys
            (user_id, credential_id, credential, created_at, updated_at)
         VALUES ($1, $2, '{}'::jsonb, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(Uuid::new_v4().into_bytes().to_vec())
    .execute(&mut *gate)
    .await
    .expect("stage concurrent Passkey registration");

    let request = tokio::spawn({
        let router = router.clone();
        async move { update_passkey_setting(&router, false).await }
    });
    let mut blocked = false;
    for _ in 0..100 {
        blocked = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1 FROM pg_locks
                 WHERE NOT granted AND locktype = 'advisory'
                   AND classid = 0 AND objid = 7341931
             )",
        )
        .fetch_one(&database)
        .await
        .expect("observe policy lock waiter");
        if blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        blocked,
        "disable request must wait for the registration policy lock"
    );
    gate.commit()
        .await
        .expect("commit staged Passkey registration");
    let response = request.await.expect("join disable request");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "passkey_disable_blocked");

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issuer_update_rechecks_passkeys_after_policy_lock() {
    let (router, database, key_directory) = setup_with_derived_webauthn(true).await;
    let (user_id, _) = create_user(&router, &database).await;
    let mut gate = database.begin().await.expect("policy gate transaction");
    sqlx::query("SELECT pg_advisory_xact_lock(0, 7341931)")
        .execute(&mut *gate)
        .await
        .expect("hold Passkey policy lock");
    sqlx::query(
        "INSERT INTO user_passkeys
            (user_id, credential_id, credential, created_at, updated_at)
         VALUES ($1, $2, '{}'::jsonb, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(Uuid::new_v4().into_bytes().to_vec())
    .execute(&mut *gate)
    .await
    .expect("stage concurrent Passkey registration");

    let request = tokio::spawn({
        let router = router.clone();
        async move {
            request(
                &router,
                "PUT",
                "/api/v1/admin/settings/issuer",
                serde_json::json!({
                    "value": "http://localhost:3000",
                    "expected_generation": 0,
                    "confirm": true
                }),
                Some("Bearer passkey-policy-token"),
            )
            .await
        }
    });
    let mut blocked = false;
    for _ in 0..100 {
        blocked = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1 FROM pg_locks
                 WHERE NOT granted AND locktype = 'advisory'
                   AND classid = 0 AND objid = 7341931
             )",
        )
        .fetch_one(&database)
        .await
        .expect("observe issuer policy lock waiter");
        if blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        blocked,
        "issuer update must wait for the registration policy lock"
    );
    gate.commit()
        .await
        .expect("commit staged Passkey registration");
    let response = request.await.expect("join issuer update");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(response).await["code"],
        "issuer_passkey_migration_required"
    );

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

async fn setup_awaiting_derived_webauthn(
    invalid_runtime: bool,
) -> (Router, sqlx::PgPool, std::path::PathBuf, IssuerRuntime) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database =
        db_isolation::isolated_pool_with_max_connections("passkey_policy", &database_url, 6).await;
    set_passkey_setting(&database, true).await;

    let key_directory =
        std::env::temp_dir().join(format!("chenxing-passkey-policy-{}", Uuid::new_v4()));
    let mut config =
        Config::from_values("127.0.0.1".to_owned(), 3000, database_url, redis_url, 3600)
            .expect("config");
    config.issuer = None;
    config.admin_token = "passkey-policy-token".to_owned();
    config.key_directory = key_directory.to_string_lossy().into_owned();
    config.auth_encryption_keys = current_key_ring();
    config.webauthn_rp_id_explicit = false;
    config.webauthn_origin_explicit = false;
    let mut state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("state");
    if invalid_runtime {
        state.issuer = IssuerRuntime::new_invalid(&state.config, 1);
    }
    let runtime = state.issuer.clone();
    assert!(
        runtime.current().is_none(),
        "regression requires no runtime snapshot"
    );
    let router = api::router(state);
    if !invalid_runtime {
        oauth_flow::ensure_owner_bootstrapped(
            &router,
            &database,
            "passkey_policy",
            "passkey_policy",
        )
        .await;
    }
    (router, database, key_directory, runtime)
}

async fn insert_user(database: &sqlx::PgPool) -> i64 {
    let suffix = Uuid::new_v4().simple().to_string();
    sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, status, created_at)
         VALUES ($1, $2, lower($2), 'test-hash', 'active', NOW())
         RETURNING id",
    )
    .bind(format!("passkey-policy-{suffix}"))
    .bind(format!("passkey-policy-{suffix}@example.com"))
    .fetch_one(database)
    .await
    .expect("insert user")
}

async fn put_issuer(
    router: &Router,
    value: &str,
    expected_generation: i64,
) -> axum::response::Response {
    request(
        router,
        "PUT",
        "/api/v1/admin/settings/issuer",
        serde_json::json!({
            "value": value,
            "expected_generation": expected_generation,
            "confirm": true
        }),
        Some("Bearer passkey-policy-token"),
    )
    .await
}

#[tokio::test]
async fn issuer_update_without_runtime_snapshot_rejects_passkey_incompatible_change() {
    let (router, database, key_directory, runtime) = setup_awaiting_derived_webauthn(false).await;
    issuer::initialize(&database, "https://auth.example.com")
        .await
        .expect("persist issuer without loading a snapshot");
    assert!(
        runtime.current().is_none(),
        "persisting issuer must not create a snapshot on this replica"
    );
    // Admin user creation goes through the issuer gate, which would converge the
    // persisted row onto this replica and destroy the no-snapshot fixture.
    let user_id = insert_user(&database).await;
    insert_passkey(&database, user_id).await;

    let response = put_issuer(&router, "https://other.example.com", 1).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(response).await["code"],
        "issuer_passkey_migration_required"
    );
    assert_eq!(
        issuer::load(&database)
            .await
            .expect("load persisted issuer")
            .expect("issuer row")
            .value,
        "https://auth.example.com"
    );
    assert!(runtime.current().is_none());

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn invalid_runtime_still_rejects_passkey_incompatible_issuer_change() {
    let (router, database, key_directory, runtime) = setup_awaiting_derived_webauthn(true).await;
    issuer::initialize(&database, "https://auth.example.com")
        .await
        .expect("persist issuer");
    let user_id = insert_user(&database).await;
    insert_passkey(&database, user_id).await;

    let response = put_issuer(&router, "https://other.example.com", 1).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(response).await["code"],
        "issuer_passkey_migration_required"
    );
    assert_eq!(
        issuer::load(&database)
            .await
            .expect("load persisted issuer")
            .expect("issuer row")
            .value,
        "https://auth.example.com"
    );
    assert!(runtime.current().is_none());

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn first_time_issuer_set_without_passkeys_does_not_require_migration() {
    let (router, database, key_directory, runtime) = setup_awaiting_derived_webauthn(false).await;
    assert_eq!(
        issuer::load(&database).await.expect("load empty issuer"),
        None
    );

    let response = put_issuer(&router, "https://auth.example.com", 0).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        issuer::load(&database)
            .await
            .expect("load persisted issuer")
            .expect("issuer row")
            .value,
        "https://auth.example.com"
    );
    assert!(runtime.current().is_some());

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn issuer_update_without_passkeys_can_change_identity_without_snapshot() {
    let (router, database, key_directory, _runtime) = setup_awaiting_derived_webauthn(false).await;
    issuer::initialize(&database, "https://auth.example.com")
        .await
        .expect("persist issuer");

    let response = put_issuer(&router, "https://other.example.com", 1).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        issuer::load(&database)
            .await
            .expect("load persisted issuer")
            .expect("issuer row")
            .value,
        "https://other.example.com"
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issuer_update_without_snapshot_rechecks_passkeys_after_policy_lock() {
    let (router, database, key_directory, runtime) = setup_awaiting_derived_webauthn(false).await;
    issuer::initialize(&database, "https://auth.example.com")
        .await
        .expect("persist issuer without loading a snapshot");
    // Same as the snapshot-free rejection test: do not create the user through
    // a gated admin route or this replica would load the persisted issuer.
    let user_id = insert_user(&database).await;
    let mut gate = database.begin().await.expect("policy gate transaction");
    sqlx::query("SELECT pg_advisory_xact_lock(0, 7341931)")
        .execute(&mut *gate)
        .await
        .expect("hold Passkey policy lock");
    sqlx::query(
        "INSERT INTO user_passkeys
            (user_id, credential_id, credential, created_at, updated_at)
         VALUES ($1, $2, '{}'::jsonb, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(Uuid::new_v4().into_bytes().to_vec())
    .execute(&mut *gate)
    .await
    .expect("stage concurrent Passkey registration");

    let request = tokio::spawn({
        let router = router.clone();
        async move { put_issuer(&router, "https://other.example.com", 1).await }
    });
    let mut blocked = false;
    for _ in 0..100 {
        blocked = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1 FROM pg_locks
                 WHERE NOT granted AND locktype = 'advisory'
                   AND classid = 0 AND objid = 7341931
             )",
        )
        .fetch_one(&database)
        .await
        .expect("observe issuer policy lock waiter");
        if blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        blocked,
        "issuer update must wait for the registration policy lock"
    );
    gate.commit()
        .await
        .expect("commit staged Passkey registration");
    let response = request.await.expect("join issuer update");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(response).await["code"],
        "issuer_passkey_migration_required"
    );
    assert_eq!(
        issuer::load(&database)
            .await
            .expect("load persisted issuer")
            .expect("issuer row")
            .value,
        "https://auth.example.com"
    );
    assert!(runtime.current().is_none());

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
