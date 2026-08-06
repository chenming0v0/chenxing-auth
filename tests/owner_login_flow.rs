use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::api;
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

#[path = "support/oauth_flow.rs"]
mod support;

use support::{cookie_header, ensure_owner_bootstrapped, json_body, test_state};

#[tokio::test]
async fn owner_login_issues_shared_session_and_csrf_cookies() {
    let (state, database, key_directory) = test_state("owner_login_flow").await;
    let router = api::router(state);
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &suffix).await;
    let username = format!("oauth-owner-{suffix}");
    let email = format!("{username}@example.com");
    let password = "correct horse battery";

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/admins")
                .header("authorization", "Bearer flow-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password,
                        "role": "owner"
                    })
                    .to_string(),
                ))
                .expect("owner creation request"),
        )
        .await
        .expect("owner creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let owner_id = json_body(response).await["id"].as_i64().expect("owner id");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "identifier": username,
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("owner login request"),
        )
        .await
        .expect("owner login response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let login_ticket = json_body(response).await["login_ticket"]
        .as_str()
        .expect("owner login ticket")
        .to_owned();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"login_ticket": login_ticket}).to_string(),
                ))
                .expect("owner TOTP setup request"),
        )
        .await
        .expect("owner TOTP setup response");
    assert_eq!(response.status(), StatusCode::OK);
    let setup = json_body(response).await;
    let totp =
        TOTP::from_url(setup["otpauth_url"].as_str().expect("owner TOTP URI")).expect("owner TOTP");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/setup/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "login_ticket": login_ticket,
                        "code": totp.generate_current().expect("owner TOTP code")
                    })
                    .to_string(),
                ))
                .expect("owner TOTP confirmation request"),
        )
        .await
        .expect("owner TOTP confirmation response");
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = cookie_header(&response);
    assert!(cookie.contains("chenxing_session="));
    assert!(cookie.contains("chenxing_csrf="));
    assert!(!cookie.contains("admin_session"));
    assert!(!cookie.contains("admin_csrf"));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("owner cookie management request"),
        )
        .await
        .expect("owner cookie management response");
    assert_eq!(response.status(), StatusCode::OK);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(owner_id)
        .execute(&database)
        .await
        .expect("cleanup owner");
    let _ = std::fs::remove_dir_all(key_directory);
}
