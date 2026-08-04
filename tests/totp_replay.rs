use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("PostgreSQL is required for TOTP replay tests");
    db::migrate(&database).await.expect("database migrations");
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
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(AppState::new(config).expect("test state")),
        database,
        key_directory,
    )
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

#[tokio::test]
async fn a_totp_time_step_is_single_use_across_tickets_and_inline_login() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("replay-{suffix}");
    let email = format!("replay-{suffix}@example.com");
    let password = "correct horse battery";
    assert_eq!(
        request(
            &router,
            "/api/v1/users",
            serde_json::json!({"username": username, "email": email, "password": password}),
        )
        .await
        .status(),
        StatusCode::CREATED
    );

    let pending = json(
        request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({"identifier": username, "password": password}),
        )
        .await,
    )
    .await;
    let setup_ticket = pending["login_ticket"].as_str().expect("setup ticket");
    let setup = json(
        request(
            &router,
            "/api/v1/auth/totp/setup",
            serde_json::json!({"login_ticket": setup_ticket}),
        )
        .await,
    )
    .await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    assert_eq!(
        request(
            &router,
            "/api/v1/auth/totp/setup/confirm",
            serde_json::json!({
                "login_ticket": setup_ticket,
                "code": totp.generate_current().expect("TOTP code")
            }),
        )
        .await
        .status(),
        StatusCode::OK
    );

    let first_ticket = json(
        request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({"identifier": email, "password": password}),
        )
        .await,
    )
    .await["login_ticket"]
        .as_str()
        .expect("first ticket")
        .to_owned();
    let second_ticket = json(
        request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({"identifier": email, "password": password}),
        )
        .await,
    )
    .await["login_ticket"]
        .as_str()
        .expect("second ticket")
        .to_owned();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let code = totp.generate(now);

    assert_eq!(
        request(
            &router,
            "/api/v1/auth/totp/login",
            serde_json::json!({"login_ticket": first_ticket, "code": code}),
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &router,
            "/api/v1/auth/totp/login",
            serde_json::json!({"login_ticket": second_ticket, "code": code}),
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
