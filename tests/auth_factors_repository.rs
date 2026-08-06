#[path = "support/db_isolation.rs"]
mod db_isolation;

use base64::Engine;
use chenxing_auth::auth_factors::repository;
use serial_test::serial;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

fn test_passkey(credential_id: &[u8]) -> Passkey {
    let encode = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    let coordinate = encode(&[4; 32]);
    serde_json::from_value(serde_json::json!({
        "cred": {
            "cred_id": encode(credential_id),
            "cred": {
                "type_": "ES256",
                "key": {
                    "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": coordinate,
                        "y": encode(&[5; 32])
                    }
                }
            },
            "counter": 0,
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

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("auth_factors_repository", &database_url).await
}

#[tokio::test]
#[serial(auth_factors_repository)]
async fn totp_factor_round_trip_returns_ciphertext_only() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, status, created_at)
         VALUES ($1, $2, $3, 'active', NOW())
         RETURNING id",
    )
    .bind(format!("factor-{suffix}"))
    .bind(format!("factor-{suffix}@example.com"))
    .bind("test-hash")
    .fetch_one(&pool)
    .await
    .expect("insert test user");

    let encrypted = vec![1_u8, 2, 3, 4];
    repository::insert_totp_factor(&pool, user_id, &encrypted)
        .await
        .expect("insert TOTP factor");
    assert_eq!(
        repository::find_totp_secret(&pool, user_id)
            .await
            .expect("find TOTP factor"),
        Some(encrypted.clone())
    );
    assert_eq!(
        repository::list_factor_methods(&pool, user_id)
            .await
            .expect("list factor methods"),
        vec!["totp".to_owned()]
    );
    assert!(
        repository::update_totp_factor_if_current(&pool, user_id, &encrypted, &[9, 8, 7])
            .await
            .expect("conditional TOTP update")
    );
    assert!(
        !repository::update_totp_factor_if_current(&pool, user_id, &encrypted, &[6, 5, 4])
            .await
            .expect("stale conditional TOTP update")
    );
    assert_eq!(
        repository::find_totp_secret(&pool, user_id)
            .await
            .expect("find migrated TOTP factor"),
        Some(vec![9, 8, 7])
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup test user");
}

#[tokio::test]
#[serial(auth_factors_repository)]
async fn passkey_insert_is_idempotent_and_rejects_cross_user_collisions() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_ids: Vec<i64> = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, status, created_at)
         VALUES ($1, $2, 'test-hash', 'active', NOW()),
                ($3, $4, 'test-hash', 'active', NOW())
         RETURNING id",
    )
    .bind(format!("passkey-{suffix}-a"))
    .bind(format!("passkey-{suffix}-a@example.com"))
    .bind(format!("passkey-{suffix}-b"))
    .bind(format!("passkey-{suffix}-b@example.com"))
    .fetch_all(&pool)
    .await
    .expect("insert test users");
    let credential_id = Uuid::new_v4().into_bytes().to_vec();
    let passkey = test_passkey(&credential_id);

    assert_eq!(
        repository::insert_passkey(&pool, user_ids[0], &credential_id, &passkey)
            .await
            .expect("insert passkey"),
        repository::PasskeyPersistenceResult::Stored
    );
    assert_eq!(
        repository::insert_passkey(&pool, user_ids[0], &credential_id, &passkey)
            .await
            .expect("repeat passkey insert"),
        repository::PasskeyPersistenceResult::Stored
    );
    let stored = repository::list_passkeys(&pool, user_ids[0])
        .await
        .expect("list passkeys");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].cred_id(), &credential_id);

    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_passkeys WHERE credential_id = $1",
        )
        .bind(&credential_id)
        .fetch_one(&pool)
        .await
        .expect("count passkeys"),
        1
    );
    assert_eq!(
        repository::insert_passkey(&pool, user_ids[1], &credential_id, &passkey)
            .await
            .expect("cross-user collision result"),
        repository::PasskeyPersistenceResult::Conflict
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&user_ids)
        .execute(&pool)
        .await
        .expect("cleanup test users");
}

#[tokio::test]
#[serial(auth_factors_repository)]
async fn first_factor_race_allows_only_one_factor_type_to_win() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple();
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, status, created_at)
         VALUES ($1, $2, 'test-hash', 'active', NOW())
         RETURNING id",
    )
    .bind(format!("first-factor-{suffix}"))
    .bind(format!("first-factor-{suffix}@example.com"))
    .fetch_one(&pool)
    .await
    .expect("insert test user");
    let credential_id = Uuid::new_v4().into_bytes().to_vec();
    let passkey = test_passkey(&credential_id);

    let (totp_result, passkey_result) = tokio::join!(
        repository::insert_totp_factor_if_empty(&pool, user_id, &[1, 2, 3]),
        repository::insert_passkey_if_empty(&pool, user_id, &credential_id, &passkey),
    );
    let totp_result = totp_result.expect("TOTP first-factor write");
    let passkey_result = passkey_result.expect("Passkey first-factor write");
    assert!(matches!(
        (totp_result, passkey_result),
        (
            repository::FirstFactorPersistenceResult::Stored,
            repository::PasskeyPersistenceResult::Conflict
        ) | (
            repository::FirstFactorPersistenceResult::AlreadyExists,
            repository::PasskeyPersistenceResult::Stored
        )
    ));
    assert_eq!(
        repository::list_factor_methods(&pool, user_id)
            .await
            .expect("list first factor"),
        if matches!(
            totp_result,
            repository::FirstFactorPersistenceResult::Stored
        ) {
            vec!["totp".to_owned()]
        } else {
            vec!["passkey".to_owned()]
        }
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup test user");
}
