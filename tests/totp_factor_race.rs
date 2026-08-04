use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup() -> (
    Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    String,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("PostgreSQL is required for TOTP race tests");
    db::migrate(&database).await.expect("database migrations");
    let key_directory = std::env::temp_dir().join(format!("chenxing-totp-race-{}", Uuid::new_v4()));
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
    let email = format!("totp-race-{}@example.com", Uuid::new_v4().simple());
    (
        api::router(AppState::new(config).expect("test state")),
        database,
        key_directory,
        email,
    )
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON response")
}

async fn request(
    router: &Router,
    uri: &str,
    payload: serde_json::Value,
) -> axum::response::Response {
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
async fn parallel_first_factor_tickets_have_only_one_winner() {
    let (router, database, key_directory, email) = setup().await;
    let username = format!("totp-race-{}", Uuid::new_v4().simple());
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

    let first_login = json_body(
        request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({"identifier": username, "password": password}),
        )
        .await,
    )
    .await;
    let first_ticket = first_login["login_ticket"]
        .as_str()
        .expect("first login ticket")
        .to_owned();
    let second_login = json_body(
        request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({"identifier": username, "password": password}),
        )
        .await,
    )
    .await;
    let second_ticket = second_login["login_ticket"]
        .as_str()
        .expect("second login ticket")
        .to_owned();

    let first_setup = json_body(
        request(
            &router,
            "/api/v1/auth/totp/setup",
            serde_json::json!({"login_ticket": first_ticket}),
        )
        .await,
    )
    .await;
    let second_setup = json_body(
        request(
            &router,
            "/api/v1/auth/totp/setup",
            serde_json::json!({"login_ticket": second_ticket}),
        )
        .await,
    )
    .await;
    let first_totp = TOTP::from_url(first_setup["otpauth_url"].as_str().expect("first TOTP URI"))
        .expect("first TOTP");
    let second_totp = TOTP::from_url(
        second_setup["otpauth_url"]
            .as_str()
            .expect("second TOTP URI"),
    )
    .expect("second TOTP");

    assert_eq!(
        request(
            &router,
            "/api/v1/auth/totp/setup/confirm",
            serde_json::json!({
                "login_ticket": first_ticket,
                "code": first_totp.generate_current().expect("first TOTP code")
            }),
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &router,
            "/api/v1/auth/totp/setup/confirm",
            serde_json::json!({
                "login_ticket": second_ticket,
                "code": second_totp.generate_current().expect("second TOTP code")
            }),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    let user_id: i64 = chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_totp_factors WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&database)
        .await
        .expect("factor count"),
        1
    );
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}
