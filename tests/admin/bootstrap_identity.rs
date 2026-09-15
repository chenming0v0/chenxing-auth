//! Bootstrap invariants: external identity creation (split from `bootstrap_invariant.rs`).

use chenxing_auth::oauth::providers::repository::{CreateIdentityError, create_user_with_identity};
use uuid::Uuid;

use super::bootstrap_invariant::{email_address, setup};

#[tokio::test]
async fn external_identity_creation_cannot_consume_id_before_owner_bootstrap() {
    let (_, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, created_at, updated_at)
         VALUES ($1, $2, lower($2), 'test-hash', NOW(), NOW())",
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
        &email_address(format!("external-{suffix}@example.com")),
        Some("External"),
        None,
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
        "INSERT INTO users (id, username, email, canonical_email, password_hash, role, created_at, updated_at)
         OVERRIDING SYSTEM VALUE
         VALUES (1, $1, $2, lower($2), 'test-hash', 'owner', NOW(), NOW())",
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
    // 同一个邮箱的两种书写：一种带空白与大写，一种是规范形态。两者规范化后
    // 匹配值相同，因此并发建号只能成功一次（Issue #302 让这条由数据库约束保证）。
    let email = email_address(format!("external-{suffix}@example.com"));
    let email_variant = email_address(format!("  EXTERNAL-{suffix}@EXAMPLE.COM  "));

    let (first, second) = tokio::join!(
        create_user_with_identity(
            &database,
            provider_id,
            &email_variant,
            Some("External 1"),
            None,
            "external-subject-1",
            "unusable-hash",
        ),
        create_user_with_identity(
            &database,
            provider_id,
            &email,
            Some("External 2"),
            None,
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

    // 按匹配值计数：胜者是哪一路由调度决定，两路的展示值不同（一路保留了大写的
    // 本地部分），但匹配值必然相同，因此只有匹配值能给出确定的断言。
    let user_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE canonical_email = $1")
            .bind(email.canonical())
            .fetch_one(&database)
            .await
            .expect("count external users");
    assert_eq!(user_count, 1);
    assert_eq!(email.canonical(), email_variant.canonical());
    let identity_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE lower(email) = $1",
    )
    .bind(email.canonical())
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
        "INSERT INTO users (id, username, email, canonical_email, password_hash, role, created_at, updated_at)
         OVERRIDING SYSTEM VALUE
         VALUES (1, $1, $2, lower($2), 'test-hash', 'owner', NOW(), NOW())",
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
    let email = email_address(format!("external-same-{suffix}@example.com"));

    let (first, second) = tokio::join!(
        create_user_with_identity(
            &database,
            provider_id,
            &email,
            Some("External 1"),
            None,
            "same-external-subject",
            "unusable-hash",
        ),
        create_user_with_identity(
            &database,
            provider_id,
            &email,
            Some("External 2"),
            None,
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
