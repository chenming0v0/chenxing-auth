use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, state::AppState};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use crate::db_isolation;

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("oauth_provider_admin_api", &database_url).await;
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
        api::router(
            AppState::new_with_pool(config, database.clone())
                .await
                .expect("state"),
        ),
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
async fn provider_admin_api_rejects_remote_http_endpoint() {
    let (router, database, key_directory) = setup().await;
    let slug = format!("remote-http-{}", Uuid::new_v4().simple());
    let mut input = provider_input(&slug);
    input["token_endpoint"] = Value::String("http://sso.example.com/oauth/token".to_owned());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/oauth/providers")
                .header("authorization", "Bearer provider-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(input.to_string()))
                .expect("provider request"),
        )
        .await
        .expect("provider response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let count: (i64,) =
        chenxing_auth::sqlx::query_as("SELECT COUNT(*) FROM oauth_providers WHERE slug = $1")
            .bind(&slug)
            .fetch_one(&database)
            .await
            .expect("provider count");
    assert_eq!(count.0, 0);

    let _ = std::fs::remove_dir_all(key_directory);
}

/// Issue #261：没有 `email_verified_claim` 的 provider 不允许落库。
///
/// 三种形态都要拦：字段缺失、显式 null、空白串。任一放过去，该 provider
/// 就能给未验证的外部邮箱自动建号。
#[tokio::test]
async fn provider_admin_api_requires_email_verified_claim() {
    let (router, database, key_directory) = setup().await;

    // 三种缺失形态：字段不存在、显式 null、空白串。
    for shape in ["missing", "null", "blank"] {
        let slug = format!("no-verified-claim-{}", Uuid::new_v4().simple());
        let mut input = provider_input(&slug);
        match shape {
            "missing" => {
                input
                    .as_object_mut()
                    .expect("object")
                    .remove("email_verified_claim");
            }
            "null" => input["email_verified_claim"] = Value::Null,
            _ => input["email_verified_claim"] = Value::String("   ".to_owned()),
        }

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/oauth/providers")
                    .header("authorization", "Bearer provider-admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(input.to_string()))
                    .expect("provider request"),
            )
            .await
            .expect("provider response");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "email_verified_claim {shape} 必须被拒绝"
        );
        assert_eq!(json(response).await["code"], "invalid_oauth_provider");

        let count: (i64,) =
            chenxing_auth::sqlx::query_as("SELECT COUNT(*) FROM oauth_providers WHERE slug = $1")
                .bind(&slug)
                .fetch_one(&database)
                .await
                .expect("provider count");
        assert_eq!(count.0, 0, "email_verified_claim {shape} 不得落库");
    }

    // 更新路径同样不允许把已有配置清空。
    let slug = format!("verified-claim-{}", Uuid::new_v4().simple());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/oauth/providers")
                .header("authorization", "Bearer provider-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(provider_input(&slug).to_string()))
                .expect("provider request"),
        )
        .await
        .expect("provider response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json(response).await;

    let mut update = provider_input(&slug);
    update["expected_version"] = created["state_version"].clone();
    update["email_verified_claim"] = Value::Null;
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
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let stored: (Option<String>,) = chenxing_auth::sqlx::query_as(
        "SELECT email_verified_claim FROM oauth_providers WHERE slug = $1",
    )
    .bind(&slug)
    .fetch_one(&database)
    .await
    .expect("stored claim");
    assert_eq!(stored.0.as_deref(), Some("email_verified"));

    chenxing_auth::sqlx::query("DELETE FROM oauth_providers WHERE slug = $1")
        .bind(&slug)
        .execute(&database)
        .await
        .expect("cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
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
    // Issue #296：契约上明确 OAuth 2.0 + UserInfo，不宣称 OIDC。
    assert_eq!(created["trust_model"], "oauth2_userinfo");
    let original_ciphertext: (Vec<u8>,) = chenxing_auth::sqlx::query_as(
        "SELECT client_secret_ciphertext FROM oauth_providers WHERE slug = $1",
    )
    .bind(&slug)
    .fetch_one(&database)
    .await
    .expect("original provider secret ciphertext");

    let mut update = provider_input(&slug);
    update["expected_version"] = created["state_version"].clone();
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
    assert_eq!(response.status(), StatusCode::OK);
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
    assert_eq!(providers[0]["trust_model"], "oauth2_userinfo");

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
        "/admin/settings"
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_providers WHERE slug = $1")
        .bind(&slug)
        .execute(&database)
        .await
        .expect("cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}
