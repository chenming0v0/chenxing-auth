use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, state::AppState};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

const ADMIN_TOKEN: &str = "totp-replay-admin-token";

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("totp_replay", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-replay-{}", Uuid::new_v4()));
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
    let router = api::router(
        AppState::new_with_pool(config, database.clone())
            .await
            .expect("test state"),
    );
    oauth_flow::ensure_owner_bootstrapped(&router, "totp_replay").await;
    db_isolation::isolate_user_ids(&database, "totp_replay").await;
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
                        "password": password,
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
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
async fn a_totp_time_step_is_single_use_across_tickets_and_inline_login() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("replay-{suffix}");
    let email = format!("replay-{suffix}@example.com");
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

    let pending_response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    let setup_cookie = pending_cookie(&pending_response);
    let _pending = json(pending_response).await;
    let setup = json(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/setup",
            serde_json::json!({}),
            &setup_cookie,
        )
        .await,
    )
    .await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/setup/confirm",
            serde_json::json!({
                "code": totp.generate_current().expect("TOTP code")
            }),
            &setup_cookie,
        )
        .await
        .status(),
        StatusCode::OK
    );

    let first_response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": email, "password": password}),
    )
    .await;
    let first_cookie = pending_cookie(&first_response);
    let _first_pending = json(first_response).await;
    let second_response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": email, "password": password}),
    )
    .await;
    let second_cookie = pending_cookie(&second_response);
    let _second_pending = json(second_response).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let code = totp.generate(now);

    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/login",
            serde_json::json!({"code": code}),
            &first_cookie,
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/login",
            serde_json::json!({"code": code}),
            &second_cookie,
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({
                "identifier": email,
                "password": password,
                "totp_code": code
            }),
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
