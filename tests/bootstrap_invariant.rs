use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::oauth::providers::repository::CreateIdentityError;
use chenxing_auth::oauth::providers::repository::create_user_with_identity;
use chenxing_auth::{api, config::Config, state::AppState};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

async fn setup() -> (
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("bootstrap_invariant", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-bootstrap-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
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
            .expect("response body"),
    )
    .expect("JSON")
}

#[tokio::test]
async fn public_registration_cannot_consume_id_before_owner_bootstrap() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("user-{suffix}"),
                        "email": format!("user-{suffix}@example.com"),
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "owner_bootstrap_required");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("owner-{suffix}"),
                        "email": format!("owner-{suffix}@example.com"),
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(json(response).await["id"], 1);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owner_bootstrap_returns_the_inserted_profile_and_rejects_repeat_calls() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("owner-{suffix}");
    let email = format!("owner-{suffix}@example.com");

    let bootstrap_request = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "username": username,
                    "email": email,
                    "password": "1234567890"
                })
                .to_string(),
            ))
            .expect("bootstrap request")
    };

    // 首次初始化必须返回事务内回查到的完整 Owner profile，而不是 panic 或空响应。
    let response = router
        .clone()
        .oneshot(bootstrap_request())
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json(response).await;
    assert_eq!(body["id"], 1);
    assert_eq!(body["username"], username);
    assert_eq!(body["email"], email);
    assert_eq!(body["role"], "owner");

    // 回查发生在事务内，因此这里返回的 profile 必须与库中持久化的行一致。
    let (stored_username, stored_status, stored_role): (String, String, String) =
        chenxing_auth::sqlx::query_as("SELECT username, status, role FROM users WHERE id = 1")
            .fetch_one(&database)
            .await
            .expect("stored owner row");
    assert_eq!(stored_username, username);
    assert_eq!(stored_status, "active");
    assert_eq!(stored_role, "owner");

    // 重复调用仍然被 Owner 唯一性不变量拒绝。
    let response = router
        .oneshot(bootstrap_request())
        .await
        .expect("repeat bootstrap response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "bootstrap_already_completed");

    let owner_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'owner'")
            .fetch_one(&database)
            .await
            .expect("owner count");
    assert_eq!(owner_count, 1);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owner_bootstrap_rejects_a_non_empty_database_without_an_owner() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, password_hash, created_at, updated_at)
         VALUES ($1, $2, 'test-hash', NOW(), NOW())",
    )
    .bind(format!("existing-{suffix}"))
    .bind(format!("existing-{suffix}@example.com"))
    .execute(&database)
    .await
    .expect("insert existing user");

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("owner-{suffix}"),
                        "email": format!("owner-{suffix}@example.com"),
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(response).await["code"],
        "owner_bootstrap_requires_empty_database"
    );

    let owner_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'owner'")
            .fetch_one(&database)
            .await
            .expect("owner count");
    assert_eq!(owner_count, 0);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn external_identity_creation_cannot_consume_id_before_owner_bootstrap() {
    let (_, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, password_hash, created_at, updated_at)
         VALUES ($1, $2, 'test-hash', NOW(), NOW())",
    )
    .bind(format!("existing-{suffix}"))
    .bind(format!("existing-{suffix}@example.com"))
    .execute(&database)
    .await
    .expect("insert existing user");
    let provider_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO oauth_providers
         (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint, client_id, created_at, updated_at)
         VALUES ('Test', $1, 'https://issuer.example/authorize', 'https://issuer.example/token',
                 'https://issuer.example/userinfo', 'test-client', NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("bootstrap-{suffix}"))
    .fetch_one(&database)
    .await
    .expect("insert provider");

    let result = create_user_with_identity(
        &database,
        provider_id,
        &format!("external-{suffix}@example.com"),
        Some("External"),
        "external-subject",
        "unusable-hash",
    )
    .await;
    assert!(
        result.is_err(),
        "external identity creation must require Owner bootstrap"
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_providers WHERE id = $1")
        .bind(provider_id)
        .execute(&database)
        .await
        .expect("cleanup provider");
    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn concurrent_external_identity_creation_rejects_duplicate_email() {
    let (_, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_email = format!("owner-{suffix}@example.com");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at)
         OVERRIDING SYSTEM VALUE
         VALUES (1, $1, $2, 'test-hash', 'owner', NOW(), NOW())",
    )
    .bind(format!("owner-{suffix}"))
    .bind(owner_email)
    .execute(&database)
    .await
    .expect("insert owner");
    chenxing_auth::sqlx::query("SELECT setval(pg_get_serial_sequence('users', 'id'), 1, true)")
        .execute(&database)
        .await
        .expect("advance users sequence");

    let provider_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO oauth_providers
         (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint, client_id, created_at, updated_at)
         VALUES ('Test', $1, 'https://issuer.example/authorize', 'https://issuer.example/token',
                 'https://issuer.example/userinfo', 'test-client', NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("concurrent-{suffix}"))
    .fetch_one(&database)
    .await
    .expect("insert provider");
    let email = format!("external-{suffix}@example.com");
    let email_variant = format!("  EXTERNAL-{suffix}@EXAMPLE.COM  ");

    let (first, second) = tokio::join!(
        create_user_with_identity(
            &database,
            provider_id,
            &email_variant,
            Some("External 1"),
            "external-subject-1",
            "unusable-hash",
        ),
        create_user_with_identity(
            &database,
            provider_id,
            &email,
            Some("External 2"),
            "external-subject-2",
            "unusable-hash",
        ),
    );
    let results = [first, second];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(CreateIdentityError::EmailAlreadyRegistered)))
            .count(),
        1
    );

    let user_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&database)
            .await
            .expect("count external users");
    assert_eq!(user_count, 1);
    let identity_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE email = $1",
    )
    .bind(&email)
    .fetch_one(&database)
    .await
    .expect("count external identities");
    assert_eq!(identity_count, 1);

    chenxing_auth::sqlx::query("DELETE FROM oauth_providers WHERE id = $1")
        .bind(provider_id)
        .execute(&database)
        .await
        .expect("cleanup provider");
    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn concurrent_external_identity_creation_reuses_the_same_identity() {
    let (_, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    chenxing_auth::sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at)
         OVERRIDING SYSTEM VALUE
         VALUES (1, $1, $2, 'test-hash', 'owner', NOW(), NOW())",
    )
    .bind(format!("owner-{suffix}"))
    .bind(format!("owner-{suffix}@example.com"))
    .execute(&database)
    .await
    .expect("insert owner");
    chenxing_auth::sqlx::query("SELECT setval(pg_get_serial_sequence('users', 'id'), 1, true)")
        .execute(&database)
        .await
        .expect("advance users sequence");

    let provider_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO oauth_providers
         (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint, client_id, created_at, updated_at)
         VALUES ('Test', $1, 'https://issuer.example/authorize', 'https://issuer.example/token',
                 'https://issuer.example/userinfo', 'test-client', NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("same-identity-{suffix}"))
    .fetch_one(&database)
    .await
    .expect("insert provider");
    let email = format!("external-same-{suffix}@example.com");

    let (first, second) = tokio::join!(
        create_user_with_identity(
            &database,
            provider_id,
            &email,
            Some("External 1"),
            "same-external-subject",
            "unusable-hash",
        ),
        create_user_with_identity(
            &database,
            provider_id,
            &email,
            Some("External 2"),
            "same-external-subject",
            "unusable-hash",
        ),
    );
    let first_id = first.expect("first external identity creation");
    let second_id = second.expect("second external identity should reuse the binding");
    assert_eq!(first_id, second_id);

    let identity_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE provider_id = $1 AND subject = $2",
    )
    .bind(provider_id)
    .bind("same-external-subject")
    .fetch_one(&database)
    .await
    .expect("count external identities");
    assert_eq!(identity_count, 1);

    chenxing_auth::sqlx::query("DELETE FROM oauth_providers WHERE id = $1")
        .bind(provider_id)
        .execute(&database)
        .await
        .expect("cleanup provider");
    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}
