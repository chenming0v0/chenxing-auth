use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::{api, clock::SharedClock};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{harness, http, oauth_flow, totp_time};

const ADMIN_TOKEN: &str = "login-security-admin-token";

async fn setup() -> (
    Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    time::OffsetDateTime,
) {
    let (state, database, key_directory, _admin_token, _binary_name) =
        harness::HarnessBuilder::new("login_security")
            .admin_token(ADMIN_TOKEN)
            .build_state()
            .await;
    let now = totp_time::centered_now();
    let state = state.with_clock(SharedClock::fixed(now));
    let router = api::router(state);
    oauth_flow::ensure_owner_bootstrapped(&router, &database, "login_security", "login-security")
        .await;
    (router, database, key_directory, now)
}

async fn request_with_cookie(
    router: &Router,
    uri: &str,
    payload: Value,
    cookie: &str,
) -> axum::response::Response {
    http::post_json_with_headers(router, uri, &[("cookie", cookie)], payload).await
}

async fn request_with_session(
    router: &Router,
    uri: &str,
    payload: Value,
    cookie: &str,
    csrf: &str,
) -> axum::response::Response {
    http::post_json_with_headers(
        router,
        uri,
        &[("cookie", cookie), ("x-csrf-token", csrf)],
        payload,
    )
    .await
}

#[tokio::test]
async fn password_success_does_not_reset_mfa_account_failures() {
    let (router, database, key_directory, now) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("security-{suffix}");
    let email = format!("security-{suffix}@example.com");
    let password = "correct horse battery";

    let response = http::post_json(
        &router,
        "/api/v1/users",
        serde_json::json!({"username": username, "email": email, "password": password}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        http::json_body(response).await["code"],
        "registration_disabled"
    );

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

    let login_response = http::post_json(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    assert_eq!(login_response.status(), StatusCode::OK);
    let session_cookie = http::set_cookies(&login_response);
    let csrf = http::cookie_value(&session_cookie, "chenxing_csrf");
    assert!(
        http::json_body(login_response).await["expires_at"]
            .as_str()
            .is_some()
    );
    let setup = http::json_body(
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
        let response = http::post_json(
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

    let pending = http::post_json(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": email, "password": password}),
    )
    .await;
    assert_eq!(pending.status(), StatusCode::ACCEPTED);
    let pending_cookie_header = http::set_cookies(&pending);
    let pending_body = http::json_body(pending).await;
    assert!(pending_body.get("login_ticket").is_none());
    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": "000000"}),
        &pending_cookie_header,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let blocked = http::post_json(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": email, "password": password}),
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);
    assert!(http::json_body(blocked).await.get("login_ticket").is_none());

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

    let login_response = http::post_json(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    assert_eq!(login_response.status(), StatusCode::OK);
    assert_eq!(cookie_max_age(&login_response, "chenxing_session"), 3600);
    assert_eq!(cookie_max_age(&login_response, "chenxing_csrf"), 3600);

    let expires_at = time::OffsetDateTime::parse(
        http::json_body(login_response).await["expires_at"]
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
