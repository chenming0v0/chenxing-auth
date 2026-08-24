use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, clock::SharedClock, config::Config, state::AppState};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{db_isolation, oauth_flow, totp_time};

const ADMIN_TOKEN: &str = "login-security-admin-token";

async fn setup() -> (
    Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    time::OffsetDateTime,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("login_security", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-login-{}", Uuid::new_v4()));
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
    let now = totp_time::centered_now();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state")
        .with_clock(SharedClock::fixed(now));
    let router = api::router(state);
    oauth_flow::ensure_owner_bootstrapped(&router, &database, "login_security", "login-security")
        .await;
    (router, database, key_directory, now)
}

async fn json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn request(router: &Router, uri: &str, payload: Value) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
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

async fn request_with_cookie(
    router: &Router,
    uri: &str,
    payload: Value,
    cookie: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

fn cookie_value(cookie: &str, name: &str) -> String {
    cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix(&format!("{name}=")))
        .expect("cookie value")
        .to_owned()
}

async fn request_with_session(
    router: &Router,
    uri: &str,
    payload: Value,
    cookie: &str,
    csrf: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

#[tokio::test]
async fn password_success_does_not_reset_mfa_account_failures() {
    let (router, database, key_directory, now) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("security-{suffix}");
    let email = format!("security-{suffix}@example.com");
    let password = "correct horse battery";

    let response = request(
        &router,
        "/api/v1/users",
        serde_json::json!({"username": username, "email": email, "password": password}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json(response).await["code"], "registration_disabled");

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
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let login_response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    assert_eq!(login_response.status(), StatusCode::OK);
    let session_cookie = pending_cookie(&login_response);
    let csrf = cookie_value(&session_cookie, "chenxing_csrf");
    assert!(json(login_response).await["expires_at"].as_str().is_some());
    let setup = json(
        request_with_session(
            &router,
            "/api/v1/auth/security/totp/enrollment/start",
            serde_json::json!({}),
            &session_cookie,
            &csrf,
        )
        .await,
    )
    .await;
    let totp =
        totp_rs::TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    let response = request_with_session(
        &router,
        "/api/v1/auth/security/totp/enrollment/confirm",
        serde_json::json!({
            "enrollment_id": setup["enrollment_id"],
            "code": totp.generate(totp_time::previous_timestep(now))
        }),
        &session_cookie,
        &csrf,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    for _ in 0..9 {
        let response = request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({
                "identifier": email,
                "password": password,
                "totp_code": "000000"
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let pending = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": email, "password": password}),
    )
    .await;
    assert_eq!(pending.status(), StatusCode::ACCEPTED);
    let pending_cookie_header = pending_cookie(&pending);
    let pending_body = json(pending).await;
    assert!(pending_body.get("login_ticket").is_none());
    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": "000000"}),
        &pending_cookie_header,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let blocked = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": email, "password": password}),
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);
    assert!(json(blocked).await.get("login_ticket").is_none());

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

const FOURTEEN_DAY_SECONDS: i64 = 14 * 24 * 60 * 60;

async fn create_user(router: &Router, username: &str, email: &str, password: &str) {
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
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
}

fn cookie_max_age(response: &axum::response::Response, name: &str) -> i64 {
    let header = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("missing {name} cookie"));
    header
        .split(';')
        .find_map(|part| {
            part.trim()
                .strip_prefix("Max-Age=")
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or_else(|| panic!("{name} cookie is missing Max-Age"))
}

/// #645：SESSION_TTL_SECONDS=3600 且没有持久化行时，本地登录必须签发 1 小时会话，
/// 不能静默变成 14 天。
#[tokio::test]
async fn missing_session_lifetime_row_honors_configured_ttl() {
    let (router, database, key_directory, now) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("ttl-{suffix}");
    let email = format!("ttl-{suffix}@example.com");
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

    let missing = chenxing_auth::sqlx::query_scalar::<_, Option<String>>(
        "SELECT setting_value FROM app_settings WHERE setting_key = 'session_lifetime'",
    )
    .fetch_optional(&database)
    .await
    .expect("session_lifetime lookup")
    .flatten();
    assert!(
        missing.as_deref().is_none_or(str::is_empty),
        "fixture must not persist a session_lifetime row"
    );

    let login_response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    assert_eq!(login_response.status(), StatusCode::OK);
    assert_eq!(cookie_max_age(&login_response, "chenxing_session"), 3600);
    assert_eq!(cookie_max_age(&login_response, "chenxing_csrf"), 3600);

    let expires_at = time::OffsetDateTime::parse(
        json(login_response).await["expires_at"]
            .as_str()
            .expect("expires_at"),
        &Rfc3339,
    )
    .expect("rfc3339 expires_at");
    assert_eq!(expires_at, now + time::Duration::seconds(3600));
    assert_ne!(
        expires_at,
        now + time::Duration::seconds(FOURTEEN_DAY_SECONDS)
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
