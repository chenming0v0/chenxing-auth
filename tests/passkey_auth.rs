use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
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
        .expect("PostgreSQL is required for passkey tests");
    db::migrate(&database).await.expect("database migrations");
    let key_directory = std::env::temp_dir().join(format!("chenxing-passkey-{}", Uuid::new_v4()));
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
    let email = format!("passkey-{}@example.com", Uuid::new_v4().simple());
    (
        api::router(AppState::new(config).expect("test state")),
        database,
        key_directory,
        email,
    )
}

async fn json_response(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn post(router: &Router, uri: &str, body: serde_json::Value) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response")
}

#[tokio::test]
async fn passkey_registration_start_returns_creation_challenge_for_login_ticket() {
    let (router, database, key_directory, email) = setup().await;
    let password = "correct horse battery";
    let response = post(
        &router,
        "/api/v1/users",
        serde_json::json!({"email": email, "password": password}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = post(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"email": email, "password": password}),
    )
    .await;
    let ticket = json_response(response).await["login_ticket"]
        .as_str()
        .expect("login ticket")
        .to_owned();

    let response = post(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({"login_ticket": ticket}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await;
    assert!(body["publicKey"]["challenge"].as_str().is_some());
    assert!(body["publicKey"]["rp"]["id"].as_str().is_some());
    assert!(body["session_id"].is_null());

    let response = post(
        &router,
        "/api/v1/auth/passkeys/register/finish",
        serde_json::json!({
            "login_ticket": ticket,
            "credential": {
                "id": "",
                "rawId": "",
                "response": {"attestationObject": "", "clientDataJSON": ""},
                "type": "public-key"
            }
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = post(
        &router,
        "/api/v1/auth/passkeys/authentication/start",
        serde_json::json!({"login_ticket": ticket}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

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
