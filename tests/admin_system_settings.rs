use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
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
        std::env::temp_dir().join(format!("chenxing-admin-system-settings-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "admin-system-settings-token".to_owned();
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

#[tokio::test]
#[serial(system_settings)]
async fn owner_can_manage_passkey_email_policy_and_smtp_settings() {
    let (router, database, key_directory) = setup().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/passkey")
                .header("authorization", "Bearer admin-system-settings-token")
                .body(Body::empty())
                .expect("passkey get"),
        )
        .await
        .expect("passkey get response");
    assert_eq!(response.status(), StatusCode::OK);
    let current = json(response).await;
    assert_eq!(current["enabled"], true);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/passkey")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "enabled": true,
                        "rp_name": "辰星认证中枢",
                        "rp_id": "localhost",
                        "user_verification": "preferred",
                        "authenticator_attachment": "any",
                        "allow_insecure_origin": true,
                        "allowed_origins": ["http://localhost:3000"]
                    })
                    .to_string(),
                ))
                .expect("passkey put"),
        )
        .await
        .expect("passkey put response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await["rp_id"], "localhost");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/email-policy")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "whitelist_enabled": true,
                        "alias_restriction_enabled": true,
                        "allowed_domains": ["example.com", "EXAMPLE.COM"]
                    })
                    .to_string(),
                ))
                .expect("email policy put"),
        )
        .await
        .expect("email policy put response");
    assert_eq!(response.status(), StatusCode::OK);
    let policy = json(response).await;
    assert_eq!(
        policy["allowed_domains"],
        serde_json::json!(["example.com"])
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/smtp")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "host": "smtp.example.com",
                        "port": 587,
                        "username": "noreply@example.com",
                        "from_address": "辰星认证中枢 <noreply@example.com>",
                        "ssl_enabled": true,
                        "force_auth_login": false,
                        "password": "super-secret-smtp"
                    })
                    .to_string(),
                ))
                .expect("smtp put"),
        )
        .await
        .expect("smtp put response");
    assert_eq!(response.status(), StatusCode::OK);
    let smtp = json(response).await;
    assert_eq!(smtp["password_configured"], true);
    assert!(smtp.get("password").is_none());
    assert!(smtp.get("password_ciphertext").is_none());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/settings/smtp")
                .header("authorization", "Bearer admin-system-settings-token")
                .body(Body::empty())
                .expect("smtp get"),
        )
        .await
        .expect("smtp get response");
    assert_eq!(response.status(), StatusCode::OK);
    let smtp = json(response).await;
    assert_eq!(smtp["host"], "smtp.example.com");
    assert_eq!(smtp["password_configured"], true);
    assert!(smtp.get("password").is_none());

    // cleanup policy to avoid affecting other registration tests
    let _ = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/email-policy")
                .header("authorization", "Bearer admin-system-settings-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "whitelist_enabled": false,
                        "alias_restriction_enabled": false,
                        "allowed_domains": []
                    })
                    .to_string(),
                ))
                .expect("email policy reset"),
        )
        .await;
    let _ = database;
    let _ = std::fs::remove_dir_all(key_directory);
}
