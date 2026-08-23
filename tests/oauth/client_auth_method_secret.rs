//! OAuth client auth_method / secret-hash pairing (Issue #580).
//!
//! `ClientCredential` already makes illegal pairs unrepresentable. Direct SQL
//! does not. The CHECK in 0040 is the database-level gate.

use crate::db_isolation;

use std::env;

use chenxing_auth::sqlx::PgPool;
use uuid::Uuid;

const MIGRATION_SQL: &str =
    include_str!("../../migrations/0040_oauth_client_auth_method_secret.sql");

const PAIRING_CHECK: &str = "(auth_method = 'none' AND client_secret_hash IS NULL)
            OR (
                auth_method IN ('client_secret_basic', 'client_secret_post')
                AND client_secret_hash IS NOT NULL
            )";

async fn database() -> PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("oauth_client_auth_method_secret", &database_url).await
}

fn is_check_violation(error: &chenxing_auth::sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23514")
}

fn database_message(error: &chenxing_auth::sqlx::Error) -> String {
    error
        .as_database_error()
        .map(|database_error| database_error.message().to_owned())
        .unwrap_or_else(|| error.to_string())
}

fn preflight_sql() -> &'static str {
    let start = MIGRATION_SQL
        .find("DO $$")
        .expect("0040 starts dirty-row refusal with a DO block");
    let end_marker = "END $$;";
    let end = MIGRATION_SQL[start..]
        .find(end_marker)
        .map(|offset| start + offset + end_marker.len())
        .expect("0040 DO block must terminate before ADD CONSTRAINT");
    MIGRATION_SQL[start..end].trim()
}

async fn insert_client(
    pool: &PgPool,
    suffix: &str,
    auth_method: &str,
    client_secret_hash: Option<&str>,
) -> Result<String, chenxing_auth::sqlx::Error> {
    let client_id = format!("auth-secret-{suffix}");
    chenxing_auth::sqlx::query(
        "INSERT INTO oauth_clients
         (client_id, client_name, client_secret_hash, redirect_uris, scopes, auth_method, created_at)
         VALUES ($1, $2, $3, '[]'::jsonb, '[]'::jsonb, $4, NOW())",
    )
    .bind(&client_id)
    .bind("Auth Method Secret Client")
    .bind(client_secret_hash)
    .bind(auth_method)
    .execute(pool)
    .await?;
    Ok(client_id)
}

#[tokio::test]
async fn pairing_constraint_matches_application_auth_methods() {
    let pool = database().await;
    let definition: String = chenxing_auth::sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid)
         FROM pg_constraint
         WHERE connamespace = current_schema()::regnamespace
           AND conrelid = 'oauth_clients'::regclass
           AND conname = 'oauth_clients_auth_method_secret_check'",
    )
    .fetch_one(&pool)
    .await
    .expect("pairing constraint");

    for needle in [
        "auth_method = 'none'",
        "client_secret_hash IS NULL",
        "client_secret_basic",
        "client_secret_post",
        "client_secret_hash IS NOT NULL",
    ] {
        assert!(
            definition.contains(needle),
            "constraint missing {needle}: {definition}"
        );
    }

    for marker in [
        "oauth_clients contain auth_method/client_secret_hash pairs that violate the credential invariant",
        "they will not be rewritten automatically",
        "CONSTRAINT oauth_clients_auth_method_secret_check",
        PAIRING_CHECK,
    ] {
        assert!(
            MIGRATION_SQL.contains(marker),
            "0040 is missing validation marker: {marker}"
        );
    }
}

#[tokio::test]
async fn legal_auth_method_secret_pairs_insert() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();

    for (label, method, hash) in [
        ("none", "none", None),
        ("basic", "client_secret_basic", Some("test-hash-basic")),
        ("post", "client_secret_post", Some("test-hash-post")),
    ] {
        insert_client(&pool, &format!("{label}-{suffix}"), method, hash)
            .await
            .unwrap_or_else(|error| panic!("{label} pair must pass CHECK: {error}"));
    }
}

#[tokio::test]
async fn illegal_auth_method_secret_pairs_are_check_violations() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();

    for (label, method, hash) in [
        ("none-with-hash", "none", Some("orphan-hash")),
        ("basic-without-hash", "client_secret_basic", None),
        ("post-without-hash", "client_secret_post", None),
    ] {
        let error = insert_client(&pool, &format!("{label}-{suffix}"), method, hash)
            .await
            .expect_err(label);
        assert!(
            is_check_violation(&error),
            "{label} must hit CHECK 23514, got {error}"
        );
    }
}

#[tokio::test]
async fn dirty_rows_fail_migration_with_client_identifiers() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();

    chenxing_auth::sqlx::query(
        "ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_auth_method_secret_check",
    )
    .execute(&pool)
    .await
    .expect("drop pairing check so illegal rows can be planted");

    let none_with_hash = insert_client(
        &pool,
        &format!("none-hash-{suffix}"),
        "none",
        Some("orphan-hash"),
    )
    .await
    .expect("none+hash is writable once CHECK is absent");
    let basic_without_hash = insert_client(
        &pool,
        &format!("basic-null-{suffix}"),
        "client_secret_basic",
        None,
    )
    .await
    .expect("basic+NULL is writable once CHECK is absent");

    let listed: Option<String> = chenxing_auth::sqlx::query_scalar(
        "SELECT string_agg(client_id, ', ' ORDER BY client_id)
         FROM oauth_clients
         WHERE NOT (
             (auth_method = 'none' AND client_secret_hash IS NULL)
             OR (
                 auth_method IN ('client_secret_basic', 'client_secret_post')
                 AND client_secret_hash IS NOT NULL
             )
         )",
    )
    .fetch_one(&pool)
    .await
    .expect("migration validation query");
    let listed = listed.expect("dirty rows must be listed");
    assert!(
        listed.contains(&none_with_hash) && listed.contains(&basic_without_hash),
        "preflight must name both dirty clients, got {listed}"
    );

    let preflight = chenxing_auth::sqlx::query(preflight_sql())
        .execute(&pool)
        .await
        .expect_err("DO block must refuse existing illegal rows");
    assert!(
        is_check_violation(&preflight),
        "dirty-row preflight must fail CHECK 23514, got {preflight}"
    );
    let message = database_message(&preflight);
    assert!(
        message.contains(&none_with_hash) && message.contains(&basic_without_hash),
        "preflight must list client_id identifiers, got {message}"
    );
    assert!(
        message.contains("will not be rewritten automatically"),
        "preflight must refuse to rewrite, got {message}"
    );

    let restore = chenxing_auth::sqlx::query(
        "ALTER TABLE oauth_clients
         ADD CONSTRAINT oauth_clients_auth_method_secret_check
             CHECK (
                 (auth_method = 'none' AND client_secret_hash IS NULL)
                 OR (
                     auth_method IN ('client_secret_basic', 'client_secret_post')
                     AND client_secret_hash IS NOT NULL
                 )
             )",
    )
    .execute(&pool)
    .await
    .expect_err("ADD CONSTRAINT must refuse the dirty rows");
    assert!(
        is_check_violation(&restore),
        "existing illegal pairs must fail CHECK 23514, got {restore}"
    );
}
