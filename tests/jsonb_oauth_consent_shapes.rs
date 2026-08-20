//! JSONB OAuth/consent/passkey shape invariants (Issue #582).
//!
//! Repositories decode these columns as `Vec<String>` or a Passkey object.
//! PostgreSQL JSONB does not care. The CHECK constraints in 0038 are the
//! database-level gate that keeps an otherwise valid row readable.

#[path = "support/db_isolation.rs"]
mod db_isolation;

use std::env;

use chenxing_auth::consents::repository::{ConsentRepository, PgConsentRepository};
use chenxing_auth::sqlx::PgPool;
use chenxing_auth::users::domain::UserId;
use serde_json::{Value, json};
use uuid::Uuid;

const MIGRATION_SQL: &str = include_str!("../migrations/0038_jsonb_oauth_consent_shapes.sql");

const STRING_ARRAY_CHECK: &str = r#"jsonb_typeof(redirect_uris) = 'array'
            AND NOT jsonb_path_exists(redirect_uris, '$[*] ? (@.type() != "string")')"#;

async fn database() -> PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("jsonb_oauth_consent_shapes", &database_url).await
}

fn is_check_violation(error: &chenxing_auth::sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23514")
}

async fn constraint_definition(pool: &PgPool, table: &str, name: &str) -> String {
    chenxing_auth::sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid)
         FROM pg_constraint
         WHERE connamespace = current_schema()::regnamespace
           AND conrelid = $1::regclass
           AND conname = $2",
    )
    .bind(table)
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|error| panic!("constraint {table}.{name}: {error}"))
}

async fn seed_user(pool: &PgPool, suffix: &str) -> UserId {
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, created_at, updated_at)
         VALUES ($1, $2, lower($2), 'test-hash', NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("jsonb-user-{suffix}"))
    .bind(format!("jsonb-{suffix}@example.com"))
    .fetch_one(pool)
    .await
    .expect("seed user")
}

async fn insert_client(
    pool: &PgPool,
    suffix: &str,
    redirect_uris: Value,
    scopes: Value,
) -> Result<(i64, String), chenxing_auth::sqlx::Error> {
    let client_id = format!("jsonb-client-{suffix}");
    let id = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, scopes, created_at)
         VALUES ($1, $2, $3, $4, NOW())
         RETURNING id",
    )
    .bind(&client_id)
    .bind("JSONB Client")
    .bind(redirect_uris)
    .bind(scopes)
    .fetch_one(pool)
    .await?;
    Ok((id, client_id))
}

#[tokio::test]
async fn jsonb_shape_constraints_match_repository_decode() {
    let pool = database().await;

    for (table, name, needles) in [
        (
            "oauth_clients",
            "oauth_clients_redirect_uris_check",
            ["jsonb_typeof(redirect_uris)", r#"@.type() != "string""#].as_slice(),
        ),
        (
            "oauth_clients",
            "oauth_clients_scopes_check",
            ["jsonb_typeof(scopes)", r#"@.type() != "string""#].as_slice(),
        ),
        (
            "user_consents",
            "user_consents_scopes_check",
            ["jsonb_typeof(scopes)", r#"@.type() != "string""#].as_slice(),
        ),
        (
            "oauth_providers",
            "oauth_providers_scopes_check",
            ["jsonb_typeof(scopes)", r#"@.type() != "string""#].as_slice(),
        ),
        (
            "user_passkeys",
            "user_passkeys_credential_check",
            ["jsonb_typeof(credential)", "'object'"].as_slice(),
        ),
    ] {
        let definition = constraint_definition(&pool, table, name).await;
        for needle in needles {
            assert!(
                definition.contains(needle),
                "{table}.{name} missing {needle}: {definition}"
            );
        }
    }

    for marker in [
        "oauth_clients contain JSONB values that cannot be decoded as string arrays",
        "user_consents contain JSONB values that cannot be decoded as string arrays",
        "oauth_providers contain JSONB values that cannot be decoded as string arrays",
        "user_passkeys contain JSONB values that cannot be decoded as a credential object",
        "they will not be rewritten automatically",
        STRING_ARRAY_CHECK,
        "CHECK (jsonb_typeof(credential) = 'object')",
    ] {
        assert!(
            MIGRATION_SQL.contains(marker),
            "0038 is missing validation marker: {marker}"
        );
    }
}

#[tokio::test]
async fn string_array_columns_reject_objects_scalars_and_wrong_element_types() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = seed_user(&pool, &suffix).await;

    let accepted = insert_client(
        &pool,
        &format!("ok-{suffix}"),
        json!(["https://client.example/callback"]),
        json!(["openid", "profile"]),
    )
    .await
    .expect("string arrays must pass CHECK");
    assert!(accepted.0 > 0);

    let empty = insert_client(&pool, &format!("empty-{suffix}"), json!([]), json!([]))
        .await
        .expect("empty arrays are the column default and must pass");
    assert!(empty.0 > 0);

    for (label, redirect_uris, scopes) in [
        ("object", json!({"https": "://x"}), json!(["openid"])),
        (
            "string-scalar",
            json!("https://client.example/cb"),
            json!(["openid"]),
        ),
        ("number", json!(1), json!(["openid"])),
        ("json-null", json!(null), json!(["openid"])),
        (
            "mixed-elements",
            json!(["https://ok.example/cb", 1]),
            json!(["openid"]),
        ),
        ("object-elements", json!([{"u": 1}]), json!(["openid"])),
        (
            "nested-array",
            json!([["https://ok.example/cb"]]),
            json!(["openid"]),
        ),
        (
            "scope-object",
            json!(["https://ok.example/cb"]),
            json!({"openid": true}),
        ),
        (
            "scope-mixed",
            json!(["https://ok.example/cb"]),
            json!(["openid", 1]),
        ),
    ] {
        let error = insert_client(&pool, &format!("{label}-{suffix}"), redirect_uris, scopes)
            .await
            .expect_err(label);
        assert!(
            is_check_violation(&error),
            "{label} must hit CHECK 23514, got {error}"
        );
    }

    let (client_pk, _) = insert_client(
        &pool,
        &format!("consent-{suffix}"),
        json!(["https://consent.example/cb"]),
        json!(["openid"]),
    )
    .await
    .expect("consent fixture client");

    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         VALUES ($1, $2, $3, NOW())",
    )
    .bind(user_id)
    .bind(client_pk)
    .bind(json!(["openid"]))
    .execute(&pool)
    .await
    .expect("string-array consent must pass");

    let consent_error = chenxing_auth::sqlx::query(
        "UPDATE user_consents SET scopes = $3 WHERE user_id = $1 AND client_id = $2",
    )
    .bind(user_id)
    .bind(client_pk)
    .bind(json!({"openid": true}))
    .execute(&pool)
    .await
    .expect_err("consent object scopes");
    assert!(is_check_violation(&consent_error));

    chenxing_auth::sqlx::query(
        "INSERT INTO oauth_providers
             (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
              client_id, scopes, created_at, updated_at)
         VALUES ('JSONB', $1, 'https://idp.example/authorize', 'https://idp.example/token',
                 'https://idp.example/userinfo', 'idp-client', $2, NOW(), NOW())",
    )
    .bind(format!("ok-{suffix}"))
    .bind(json!(["openid", "email"]))
    .execute(&pool)
    .await
    .expect("string-array provider scopes must pass");

    let provider_error = chenxing_auth::sqlx::query(
        "INSERT INTO oauth_providers
             (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
              client_id, scopes, created_at, updated_at)
         VALUES ('JSONB', $1, 'https://idp.example/authorize', 'https://idp.example/token',
                 'https://idp.example/userinfo', 'idp-client', $2, NOW(), NOW())",
    )
    .bind(format!("bad-{suffix}"))
    .bind(json!("openid"))
    .execute(&pool)
    .await
    .expect_err("provider scalar scopes");
    assert!(is_check_violation(&provider_error));
}

#[tokio::test]
async fn passkey_credential_must_be_a_json_object() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = seed_user(&pool, &suffix).await;

    for (label, credential) in [
        ("empty-object", json!({})),
        ("cred-envelope", json!({"cred": {}})),
    ] {
        chenxing_auth::sqlx::query(
            "INSERT INTO user_passkeys (user_id, credential_id, credential, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(format!("{label}-{suffix}").into_bytes())
        .bind(credential)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("{label} object must pass: {error}"));
    }

    for (label, credential) in [
        ("array", json!([])),
        ("string", json!("cred")),
        ("number", json!(1)),
        ("json-null", json!(null)),
    ] {
        let error = chenxing_auth::sqlx::query(
            "INSERT INTO user_passkeys (user_id, credential_id, credential, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(format!("{label}-{suffix}").into_bytes())
        .bind(credential)
        .execute(&pool)
        .await
        .expect_err(label);
        assert!(
            is_check_violation(&error),
            "{label} must hit CHECK 23514, got {error}"
        );
    }
}

#[tokio::test]
async fn adding_the_constraint_fails_closed_on_existing_malformed_rows() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();

    chenxing_auth::sqlx::query(
        "ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_redirect_uris_check",
    )
    .execute(&pool)
    .await
    .expect("drop redirect_uris check so a malformed row can be planted");

    let (_, client_id) = insert_client(
        &pool,
        &format!("dirty-{suffix}"),
        json!({"not": "an array"}),
        json!(["openid"]),
    )
    .await
    .expect("malformed row is writable once CHECK is absent");

    let listed: Option<String> = chenxing_auth::sqlx::query_scalar(
        "SELECT string_agg(client_id, ', ' ORDER BY client_id)
         FROM oauth_clients
         WHERE jsonb_typeof(redirect_uris) <> 'array'
            OR jsonb_path_exists(redirect_uris, '$[*] ? (@.type() != \"string\")')",
    )
    .fetch_one(&pool)
    .await
    .expect("migration validation query");
    assert_eq!(listed.as_deref(), Some(client_id.as_str()));

    let restore = chenxing_auth::sqlx::query(
        "ALTER TABLE oauth_clients
         ADD CONSTRAINT oauth_clients_redirect_uris_check
             CHECK (
                 jsonb_typeof(redirect_uris) = 'array'
                 AND NOT jsonb_path_exists(redirect_uris, '$[*] ? (@.type() != \"string\")')
             )",
    )
    .execute(&pool)
    .await
    .expect_err("ADD CONSTRAINT must refuse the malformed row");
    assert!(
        is_check_violation(&restore),
        "existing malformed JSONB must fail CHECK 23514, got {restore}"
    );
}

#[tokio::test]
async fn repositories_cannot_decode_malformed_rows_that_bypass_the_check() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = seed_user(&pool, &suffix).await;

    chenxing_auth::sqlx::query(
        "ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_redirect_uris_check",
    )
    .execute(&pool)
    .await
    .expect("drop client redirect_uris check");
    let (_, client_id) = insert_client(
        &pool,
        &format!("decode-{suffix}"),
        json!({"https": "://x"}),
        json!(["openid"]),
    )
    .await
    .expect("plant malformed client");
    let client_error = chenxing_auth::clients::repository::find_client_by_id(&pool, &client_id)
        .await
        .expect_err("object redirect_uris must fail Json<Vec<String>>");
    assert!(
        matches!(client_error, chenxing_auth::sqlx::Error::Decode(_)),
        "client decode must be Decode, got {client_error}"
    );

    let (client_pk, consent_client_id) = insert_client(
        &pool,
        &format!("consent-decode-{suffix}"),
        json!(["https://ok.example/cb"]),
        json!(["openid"]),
    )
    .await
    .expect("consent fixture client");
    chenxing_auth::sqlx::query(
        "ALTER TABLE user_consents DROP CONSTRAINT user_consents_scopes_check",
    )
    .execute(&pool)
    .await
    .expect("drop consent scopes check");
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         VALUES ($1, $2, $3, NOW())",
    )
    .bind(user_id)
    .bind(client_pk)
    .bind(json!({"openid": true}))
    .execute(&pool)
    .await
    .expect("plant malformed consent");
    let consents = PgConsentRepository::new(pool.clone());
    let consent_error = consents
        .stored_scopes(user_id, &consent_client_id)
        .await
        .expect_err("object consent scopes must fail Json<Vec<String>>");
    assert!(
        matches!(consent_error, chenxing_auth::sqlx::Error::Decode(_)),
        "consent decode must be Decode, got {consent_error}"
    );

    chenxing_auth::sqlx::query(
        "ALTER TABLE oauth_providers DROP CONSTRAINT oauth_providers_scopes_check",
    )
    .execute(&pool)
    .await
    .expect("drop provider scopes check");
    let slug = format!("decode-{suffix}");
    chenxing_auth::sqlx::query(
        "INSERT INTO oauth_providers
             (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint,
              client_id, scopes, created_at, updated_at)
         VALUES ('JSONB', $1, 'https://idp.example/authorize', 'https://idp.example/token',
                 'https://idp.example/userinfo', 'idp-client', $2, NOW(), NOW())",
    )
    .bind(&slug)
    .bind(json!({"openid": true}))
    .execute(&pool)
    .await
    .expect("plant malformed provider");
    let provider_error = chenxing_auth::oauth::providers::repository::find_by_slug(&pool, &slug)
        .await
        .expect_err("object provider scopes must fail Vec<String> decode");
    assert!(
        matches!(provider_error, chenxing_auth::sqlx::Error::Decode(_)),
        "provider decode must be Decode, got {provider_error}"
    );

    chenxing_auth::sqlx::query(
        "ALTER TABLE user_passkeys DROP CONSTRAINT user_passkeys_credential_check",
    )
    .execute(&pool)
    .await
    .expect("drop passkey credential check");
    chenxing_auth::sqlx::query(
        "INSERT INTO user_passkeys (user_id, credential_id, credential, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(b"malformed-passkey".as_slice())
    .bind(json!(["not", "an", "object"]))
    .execute(&pool)
    .await
    .expect("plant malformed passkey");
    let passkey_error = chenxing_auth::auth_factors::repository::list_passkeys(&pool, user_id)
        .await
        .expect_err("array credential must fail Passkey decode");
    assert!(
        matches!(passkey_error, chenxing_auth::sqlx::Error::Decode(_)),
        "passkey decode must be Decode, got {passkey_error}"
    );
}
