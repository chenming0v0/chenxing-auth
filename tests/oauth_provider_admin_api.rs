use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
use serde_json::Value;
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
        std::env::temp_dir().join(format!("chenxing-provider-admin-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "provider-admin-token".to_owned();
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

fn provider_input(slug: &str) -> Value {
    serde_json::json!({
        "name": "企业 SSO",
        "slug": slug,
        "authorization_endpoint": "https://sso.example.com/oauth/authorize",
        "token_endpoint": "https://sso.example.com/oauth/token",
        "userinfo_endpoint": "https://sso.example.com/oauth/userinfo",
        "client_id": "client-id",
        "client_secret": "client-secret",
        "scopes": ["openid", "profile", "email"],
        "subject_claim": "sub",
        "email_claim": "email",
        "name_claim": "name",
        "email_verified_claim": "email_verified",
        "client_auth_method": "basic"
    })
}

#[tokio::test]
async fn provider_admin_api_requires_auth_and_never_returns_client_secret() {
    let (router, database, key_directory) = setup().await;
    let slug = format!("provider-{}", Uuid::new_v4().simple());
    let body = provider_input(&slug).to_string();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/oauth/providers")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/oauth/providers")
                .header("authorization", "Bearer provider-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json(response).await;
    assert_eq!(created["slug"], slug);
    assert_eq!(created["client_secret_configured"], true);
    assert!(created.get("client_secret").is_none());
    let original_ciphertext: (Vec<u8>,) = chenxing_auth::sqlx::query_as(
        "SELECT client_secret_ciphertext FROM oauth_providers WHERE slug = $1",
    )
    .bind(&slug)
    .fetch_one(&database)
    .await
    .expect("original provider secret ciphertext");

    let mut update = provider_input(&slug);
    update["name"] = Value::String("更新后的企业 SSO".to_owned());
    update["client_secret"] = Value::Null;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/oauth/providers/{slug}"))
                .header("authorization", "Bearer provider-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(update.to_string()))
                .expect("update request"),
        )
        .await
        .expect("update response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let preserved_ciphertext: (Vec<u8>,) = chenxing_auth::sqlx::query_as(
        "SELECT client_secret_ciphertext FROM oauth_providers WHERE slug = $1",
    )
    .bind(&slug)
    .fetch_one(&database)
    .await
    .expect("preserved provider secret ciphertext");
    assert_eq!(preserved_ciphertext.0, original_ciphertext.0);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/oauth/providers")
                .header("authorization", "Bearer provider-admin-token")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let providers = json(response).await;
    assert_eq!(providers[0]["client_secret_configured"], true);
    assert!(providers[0].get("client_secret").is_none());

    // The legacy server-rendered settings page now forwards to the React console;
    // the API-level assertions above already guarantee the client secret is never
    // returned to callers.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/settings/oauth")
                .header("authorization", "Bearer provider-admin-token")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[axum::http::header::LOCATION],
        "/console/settings"
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_providers WHERE slug = $1")
        .bind(&slug)
        .execute(&database)
        .await
        .expect("cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}
