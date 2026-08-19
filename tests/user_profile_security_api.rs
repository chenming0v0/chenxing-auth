use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use chenxing_auth::api;
use serde_json::Value;
use tower::ServiceExt;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

const PASSWORD: &str = "correct horse battery";

fn csrf_token(cookie: &str) -> &str {
    cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
}

async fn json_body(response: axum::response::Response) -> Value {
    oauth_flow::json_body(response).await
}

#[tokio::test]
async fn username_change_requires_current_password() {
    let (state, database, key_directory) =
        oauth_flow::test_state("user_profile_security_api").await;
    let router: Router = api::router(state);
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
    let csrf = csrf_token(&cookie).to_owned();

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
        json_body(response).await["code"],
        "current_password_required"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}
