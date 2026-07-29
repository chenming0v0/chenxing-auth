use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
use totp_rs::{Secret, TOTP};
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
        .expect("PostgreSQL is required for TOTP tests");
    db::migrate(&database).await.expect("database migrations");
    let key_directory = std::env::temp_dir().join(format!("chenxing-totp-{}", Uuid::new_v4()));
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
    let email = format!("totp-{}@example.com", Uuid::new_v4().simple());
    (
        api::router(AppState::new(config).expect("test state")),
        database,
        key_directory,
        email,
    )
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
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
async fn password_login_without_factor_returns_pending_setup_ticket() {
    let (router, database, key_directory, email) = setup().await;
    let password = "correct horse battery";
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = json_body(response).await;
    assert_eq!(body["status"], "factor_setup_required");
    assert!(
        body["login_ticket"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(body["methods"][0], "totp");

    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn totp_setup_confirm_issues_session_and_consumes_ticket() {
    let (router, database, key_directory, email) = setup().await;
    let password = "correct horse battery";
    let response = request(
        &router,
        "/api/v1/users",
        serde_json::json!({"email": email, "password": password}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"email": email, "password": password}),
    )
    .await;
    let ticket = json_body(response).await["login_ticket"]
        .as_str()
        .expect("login ticket")
        .to_owned();

    let response = request(
        &router,
        "/api/v1/auth/totp/setup",
        serde_json::json!({"login_ticket": ticket}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let setup = json_body(response).await;
    let secret = setup["secret_base32"].as_str().expect("TOTP secret");
    let uri = setup["otpauth_url"].as_str().expect("otpauth URI");
    assert!(uri.starts_with("otpauth://totp/"));
    let totp = TOTP::from_url(uri).expect("TOTP URI");
    assert_eq!(totp.get_secret_base32(), secret);
    let code = totp.generate_current().expect("current TOTP code");

    let response = request(
        &router,
        "/api/v1/auth/totp/setup/confirm",
        serde_json::json!({"login_ticket": ticket, "code": "000000"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = request(
        &router,
        "/api/v1/auth/totp/setup/confirm",
        serde_json::json!({"login_ticket": ticket, "code": code}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-cookie").is_some());
    let session_body = json_body(response).await;
    assert!(session_body["session_id"].as_str().is_some());

    let response = request(
        &router,
        "/api/v1/auth/totp/setup/confirm",
        serde_json::json!({"login_ticket": ticket, "code": code}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"email": email, "password": password}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(json_body(response).await["status"], "factor_required");

    let login_ticket = json_body(
        request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({"email": email, "password": password}),
        )
        .await,
    )
    .await["login_ticket"]
        .as_str()
        .expect("login ticket")
        .to_owned();
    let response = request(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({"login_ticket": login_ticket}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"email": email, "password": password, "totp_code": "000000"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let secret_bytes = Secret::Encoded(secret.to_owned())
        .to_bytes()
        .expect("secret bytes");
    let valid_code = TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        None,
        String::new(),
    )
    .expect("TOTP");
    let response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({
            "email": email,
            "password": password,
            "totp_code": valid_code.generate_current().expect("valid code")
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}
