use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, sqlx, state::AppState};
use serde_json::Value;
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

const PASSWORD: &str = "correct horse battery";

async fn setup() -> (Router, sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("passkey_policy", &database_url).await;
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
    sqlx::query(
        "INSERT INTO user_totp_factors
            (user_id, encrypted_secret, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(user_id)
    .bind([1_u8, 2, 3, 4].as_slice())
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
async fn disabled_passkey_policy_exposes_only_recoverable_factor_methods() {
    let (router, database, key_directory) = setup().await;
    let (passkey_user, passkey_username) = create_user(&router, &database).await;
    let (totp_user, totp_username) = create_user(&router, &database).await;
    let (mixed_user, mixed_username) = create_user(&router, &database).await;
    let (empty_user, empty_username) = create_user(&router, &database).await;
    insert_passkey(&database, passkey_user).await;
    insert_totp(&database, totp_user).await;
    insert_passkey(&database, mixed_user).await;
    insert_totp(&database, mixed_user).await;

    assert_eq!(
        login(&router, &passkey_username).await["methods"],
        serde_json::json!(["passkey"])
    );
    assert_eq!(
        login(&router, &totp_username).await["methods"],
        serde_json::json!(["totp"])
    );
    assert_eq!(
        login(&router, &mixed_username).await["methods"],
        serde_json::json!(["passkey", "totp"])
    );
    assert_eq!(
        login(&router, &empty_username).await["methods"],
        serde_json::Value::Null
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
    assert_eq!(
        login(&router, &passkey_username).await["methods"],
        serde_json::json!(["passkey"])
    );
    assert_eq!(
        login(&router, &totp_username).await["methods"],
        serde_json::json!(["totp"])
    );
    assert_eq!(
        login(&router, &mixed_username).await["methods"],
        serde_json::json!(["passkey", "totp"])
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
