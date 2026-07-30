use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
use chenxing_auth::{
    sessions::{cookies, domain::Session, store::SessionStore},
    sqlx,
};
use serde_json::Value;
use serial_test::serial;
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
        .expect("PostgreSQL");
    db::migrate(&database).await.expect("migrations");
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-admin-settings-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "admin-settings-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(AppState::new(config).expect("state")),
        database,
        key_directory,
    )
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("JSON")
}

async fn browser_session(database_url: &str, redis_url: &str, user_id: i64) -> (String, String) {
    let database = PgPoolOptions::new()
        .max_connections(2)
        .connect(database_url)
        .await
        .expect("session PostgreSQL");
    let redis = redis::Client::open(redis_url).expect("session Redis");
    let store = SessionStore::with_metadata(redis, database);
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("browser session");
    store
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("save browser session");
    let cookie = format!(
        "{}={}; {}={}",
        cookies::SESSION_COOKIE,
        session.token,
        cookies::CSRF_COOKIE,
        session.csrf_token
    );
    (cookie, session.csrf_token)
}

#[tokio::test]
#[serial(registration_email_setting)]
async fn owner_can_read_update_and_persist_registration_email_setting() {
    let (router, database, key_directory) = setup().await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .body(Body::empty())
                .expect("settings request"),
        )
        .await
        .expect("settings response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        json(response)
            .await
            .get("registration_email_from")
            .is_some()
    );

    let email = format!("registration-{}@example.com", Uuid::new_v4().simple());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"registration_email_from": "not-an-email"}).to_string(),
                ))
                .expect("invalid settings request"),
        )
        .await
        .expect("invalid settings response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "invalid_email");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("missing settings field request"),
        )
        .await
        .expect("missing settings field response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "invalid_request");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"registration_email_from": email}).to_string(),
                ))
                .expect("unauthorized settings request"),
        )
        .await
        .expect("unauthorized settings response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("authorization", "Bearer admin-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"registration_email_from": email}).to_string(),
                ))
                .expect("update settings request"),
        )
        .await
        .expect("update settings response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await["registration_email_from"], email);

    let stored: Option<String> = chenxing_auth::sqlx::query_scalar(
        "SELECT setting_value FROM app_settings WHERE setting_key = 'registration_email_from'",
    )
    .fetch_one(&database)
    .await
    .expect("stored setting");
    assert_eq!(stored.as_deref(), Some(email.as_str()));

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial(registration_email_setting)]
async fn session_authenticated_setting_mutation_records_user_actor() {
    let (router, database, key_directory) = setup().await;
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let username = format!("settings-owner-{}", Uuid::new_v4().simple());
    let email = format!("{username}@example.com");
    let user_id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, 'test-hash', 'owner', NOW(), NOW())
         RETURNING id",
    )
    .bind(&username)
    .bind(&email)
    .fetch_one(&database)
    .await
    .expect("owner user");
    let (cookie, csrf) = browser_session(&database_url, &redis_url, user_id).await;
    let registration_email = format!("sender-{}@example.com", Uuid::new_v4().simple());

    let response = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration-email")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"registration_email_from": registration_email}).to_string(),
                ))
                .expect("session setting request"),
        )
        .await
        .expect("session setting response");
    assert_eq!(response.status(), StatusCode::OK);

    let actor: Option<i64> = sqlx::query_scalar(
        "SELECT actor_user_id FROM audit_events
         WHERE action = 'registration_email_update' AND resource_id = $1
         ORDER BY id DESC LIMIT 1",
    )
    .bind(chenxing_auth::settings::REGISTRATION_EMAIL_FROM_KEY)
    .fetch_one(&database)
    .await
    .expect("registration audit event");
    assert_eq!(actor, Some(user_id));

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup owner");
    let _ = std::fs::remove_dir_all(key_directory);
}
