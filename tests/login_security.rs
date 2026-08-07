use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, state::AppState};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
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
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let router = api::router(
        AppState::new_with_pool(config, database.clone())
            .await
            .expect("test state"),
    );
    oauth_flow::ensure_owner_bootstrapped(&router, "login-security").await;
    (router, database, key_directory)
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

#[tokio::test]
async fn password_success_does_not_reset_mfa_account_failures() {
    let (router, database, key_directory) = setup().await;
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
    assert_eq!(response.status(), StatusCode::CREATED);

    let pending_response = request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({"identifier": username, "password": password}),
        )
        .await;
    let pending_cookie_header = pending_cookie(&pending_response);
    let pending = json(pending_response).await;
    assert!(pending.get("login_ticket").is_none());
    let setup = json(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/setup",
            serde_json::json!({}),
            &pending_cookie_header,
        )
        .await,
    )
    .await;
    let totp =
        totp_rs::TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/setup/confirm",
        serde_json::json!({
            "code": totp.generate_current().expect("TOTP code")
        }),
        &pending_cookie_header,
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
