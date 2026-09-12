use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use tower::ServiceExt;

use crate::{harness, http, oauth_flow};

const PASSWORD: &str = "correct horse battery";

#[tokio::test]
async fn username_change_requires_current_password() {
    let harness::Harness {
        router,
        database,
        key_directory,
        ..
    } = harness::HarnessBuilder::new("user_profile_security_api")
        // 原 `oauth_flow::test_state` 会放大 QPS 窗口，保持一致。
        .qps_window_override()
        .build()
        .await;
    oauth_flow::ensure_owner_bootstrapped(
        &router,
        &database,
        "user_profile_security_api",
        "username-change",
    )
    .await;
    let (_user_id, username, _email, _password) =
        oauth_flow::register_test_user(&router, "username-change").await;

    let login = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"identifier": username, "password": PASSWORD}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = oauth_flow::cookie_header(&login);
    let csrf = http::cookie_value(&cookie, "chenxing_csrf");

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/api/v1/auth/me")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .header("x-csrf-token", csrf)
                .body(Body::from(
                    serde_json::json!({"username": "renamed-user"}).to_string(),
                ))
                .expect("profile update request"),
        )
        .await
        .expect("profile update response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        http::json_body(response).await["code"],
        "current_password_required"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}
