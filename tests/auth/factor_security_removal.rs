//! Passing-key factor removal invariants (split from `factor_security_totp.rs`).

use axum::http::{Method, StatusCode, header::SET_COOKIE};
use totp_rs::TOTP;

use crate::{http, totp_time};

use super::factor_security_api::{PASSWORD, TestApp, confirm_totp, csrf, start_totp};

#[tokio::test]
async fn factor_removal_requires_password_and_revokes_current_session() {
    let app = TestApp::new("factor_security_remove").await;
    let (user_id, username, _) = app.create_user().await;
    let login = app.login(&username, PASSWORD).await;
    let cookie = http::set_cookies(&login);
    let csrf_token = csrf(&cookie);
    let setup = start_totp(&app, &cookie, &csrf_token).await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("otpauth URL")).expect("TOTP");
    let confirmed = confirm_totp(
        &app,
        &cookie,
        &csrf_token,
        setup["enrollment_id"].as_str().expect("enrollment id"),
        &totp.generate(totp_time::previous_timestep(app.now)),
    )
    .await;
    assert_eq!(confirmed.status(), StatusCode::OK);

    let wrong = app
        .request(
            Method::DELETE,
            "/api/v1/auth/security/factors/totp",
            serde_json::json!({"password": "wrong password"}),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let still_enabled: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_totp_factors WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("TOTP state");
    assert!(still_enabled);

    let removed = app
        .request(
            Method::DELETE,
            "/api/v1/auth/security/factors/totp",
            serde_json::json!({"password": PASSWORD}),
            None,
            Some((&cookie, &csrf_token)),
        )
        .await;
    assert_eq!(removed.status(), StatusCode::OK);
    let clear_cookie = removed
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(clear_cookie.contains("Max-Age=0"));

    let session_after = app
        .request(
            Method::GET,
            "/api/v1/auth/security/factors",
            serde_json::json!({}),
            Some(("cookie", cookie.clone())),
            None,
        )
        .await;
    assert_eq!(session_after.status(), StatusCode::UNAUTHORIZED);
    let factor_exists: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_totp_factors WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("TOTP state");
    assert!(!factor_exists);
    let audit_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE actor_user_id = $1 AND action = 'user_totp_factor_remove'",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("removal audit");
    assert_eq!(audit_count, 1);
}
