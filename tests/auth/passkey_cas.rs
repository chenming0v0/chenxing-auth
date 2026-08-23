use crate::db_isolation;

use base64::Engine;
use chenxing_auth::auth_factors::repository;
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

fn encode(value: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

fn test_passkey(credential_id: &[u8], counter: u32) -> Passkey {
    serde_json::from_value(serde_json::json!({
        "cred": {
            "cred_id": encode(credential_id),
            "cred": {
                "type_": "ES256",
                "key": {
                    "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": encode(&[4; 32]),
                        "y": encode(&[5; 32])
                    }
                }
            },
            "counter": counter,
            "transports": null,
            "user_verified": false,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "required",
            "extensions": {},
            "attestation": {"data": "None", "metadata": "None"},
            "attestation_format": "none"
        }
    }))
    .expect("test passkey")
}

fn authentication_result(credential_id: &[u8], counter: u32) -> AuthenticationResult {
    serde_json::from_value(serde_json::json!({
        "cred_id": encode(credential_id),
        "needs_update": true,
        "user_verified": true,
        "backup_state": false,
        "backup_eligible": false,
        "counter": counter,
        "extensions": {}
    }))
    .expect("authentication result")
}

fn counter_of(passkey: &Passkey) -> u32 {
    serde_json::to_value(passkey).expect("passkey JSON")["cred"]["counter"]
        .as_u64()
        .expect("counter") as u32
}

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool_with_max_connections("passkey_cas", &database_url, 8).await
}

async fn insert_user(pool: &chenxing_auth::sqlx::PgPool, label: &str) -> i64 {
    let suffix = Uuid::new_v4().simple();
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, status, created_at)
         VALUES ($1, $2, lower($2), 'test-hash', 'active', NOW())
         RETURNING id",
    )
    .bind(format!("{label}-{suffix}"))
    .bind(format!("{label}-{suffix}@example.com"))
    .fetch_one(pool)
    .await
    .expect("insert user")
}

async fn cleanup_user(pool: &chenxing_auth::sqlx::PgPool, user_id: i64) {
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("cleanup user");
}

#[tokio::test]
async fn persist_keeps_newer_counter_when_stale_result_loses_cas() {
    let pool = database().await;
    let user_id = insert_user(&pool, "passkey-merge").await;
    let credential_id = Uuid::new_v4().into_bytes().to_vec();
    repository::insert_passkey_if_empty(
        &pool,
        user_id,
        0,
        &credential_id,
        &test_passkey(&credential_id, 0),
    )
    .await
    .expect("insert passkey");
    let stored = repository::list_passkeys_with_versions(&pool, user_id)
        .await
        .expect("load passkey")
        .pop()
        .expect("stored passkey");

    let newer = authentication_result(&credential_id, 2);
    assert_eq!(
        repository::persist_passkey_authentication(
            &pool,
            user_id,
            stored.id,
            &credential_id,
            &newer,
        )
        .await
        .expect("persist newer counter"),
        repository::PasskeyPersistOutcome::Applied
    );

    let stale = authentication_result(&credential_id, 1);
    assert_eq!(
        repository::persist_passkey_authentication(
            &pool,
            user_id,
            stored.id,
            &credential_id,
            &stale,
        )
        .await
        .expect("persist stale counter"),
        repository::PasskeyPersistOutcome::AlreadyCurrent
    );

    let persisted = repository::find_passkey_row(&pool, user_id, stored.id)
        .await
        .expect("reload")
        .expect("row still present");
    assert_eq!(counter_of(persisted.passkey()), 2);
    assert_eq!(persisted.state_version, stored.state_version + 1);

    cleanup_user(&pool, user_id).await;
}

#[tokio::test]
async fn persist_does_not_touch_re_registered_row_with_same_credential_id() {
    let pool = database().await;
    let user_id = insert_user(&pool, "passkey-rereg").await;
    let credential_id = Uuid::new_v4().into_bytes().to_vec();
    repository::insert_passkey_if_empty(
        &pool,
        user_id,
        0,
        &credential_id,
        &test_passkey(&credential_id, 0),
    )
    .await
    .expect("insert passkey");
    let original = repository::list_passkeys_with_versions(&pool, user_id)
        .await
        .expect("load original")
        .pop()
        .expect("original row");

    chenxing_auth::sqlx::query("DELETE FROM user_passkeys WHERE id = $1")
        .bind(original.id)
        .execute(&pool)
        .await
        .expect("delete original row");
    repository::insert_passkey_if_empty(
        &pool,
        user_id,
        0,
        &credential_id,
        &test_passkey(&credential_id, 0),
    )
    .await
    .expect("re-register same credential id");
    let replacement = repository::list_passkeys_with_versions(&pool, user_id)
        .await
        .expect("load replacement")
        .pop()
        .expect("replacement row");
    assert_ne!(replacement.id, original.id);

    let stale = authentication_result(&credential_id, 3);
    assert_eq!(
        repository::persist_passkey_authentication(
            &pool,
            user_id,
            original.id,
            &credential_id,
            &stale,
        )
        .await
        .expect("persist against deleted row"),
        repository::PasskeyPersistOutcome::Missing
    );

    let after = repository::find_passkey_row(&pool, user_id, replacement.id)
        .await
        .expect("reload replacement")
        .expect("replacement still present");
    assert_eq!(after.state_version, replacement.state_version);
    assert_eq!(counter_of(after.passkey()), 0);

    cleanup_user(&pool, user_id).await;
}

#[tokio::test]
async fn persist_does_not_claim_success_when_row_is_gone() {
    let pool = database().await;
    let user_id = insert_user(&pool, "passkey-missing").await;
    let credential_id = Uuid::new_v4().into_bytes().to_vec();
    repository::insert_passkey_if_empty(
        &pool,
        user_id,
        0,
        &credential_id,
        &test_passkey(&credential_id, 0),
    )
    .await
    .expect("insert passkey");
    let stored = repository::list_passkeys_with_versions(&pool, user_id)
        .await
        .expect("load passkey")
        .pop()
        .expect("stored passkey");

    chenxing_auth::sqlx::query("DELETE FROM user_passkeys WHERE id = $1")
        .bind(stored.id)
        .execute(&pool)
        .await
        .expect("delete row");

    assert_eq!(
        repository::persist_passkey_authentication(
            &pool,
            user_id,
            stored.id,
            &credential_id,
            &authentication_result(&credential_id, 1),
        )
        .await
        .expect("persist after delete"),
        repository::PasskeyPersistOutcome::Missing
    );

    cleanup_user(&pool, user_id).await;
}
