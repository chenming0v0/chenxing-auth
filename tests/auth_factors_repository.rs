#[path = "support/db_isolation.rs"]
mod db_isolation;

use base64::Engine;
use chenxing_auth::auth_factors::repository;
use std::sync::Arc;
use tokio::sync::Barrier;
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

fn test_passkey_with_counter(credential_id: &[u8], counter: u32) -> Passkey {
    let mut value = serde_json::to_value(test_passkey(credential_id)).expect("passkey JSON");
    value["cred"]["counter"] = serde_json::json!(counter);
    serde_json::from_value(value).expect("passkey with counter")
}

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    // The first-factor race must have enough connections for both writes to
    // reach PostgreSQL at the same time; the default two-connection pool is
    // also shared by setup/cleanup work and can serialize the contenders.
    db_isolation::isolated_pool_with_max_connections("auth_factors_repository", &database_url, 8)
        .await
}

#[tokio::test]
async fn totp_factor_round_trip_returns_ciphertext_only() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, status, created_at)
         VALUES ($1, $2, lower($2), $3, 'active', NOW())
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
    assert_eq!(
        repository::update_totp_factor_if_current(&pool, user_id, &encrypted, &[9, 8, 7])
            .await
            .expect("conditional TOTP update"),
        repository::TotpCasUpdateOutcome::Updated
    );
    assert_eq!(
        repository::update_totp_factor_if_current(&pool, user_id, &encrypted, &[6, 5, 4])
            .await
            .expect("stale conditional TOTP update"),
        repository::TotpCasUpdateOutcome::Superseded
    );
    assert_eq!(
        repository::find_totp_secret(&pool, user_id)
            .await
            .expect("find migrated TOTP factor"),
        Some(vec![9, 8, 7])
    );
    // #360：CAS 未命中必须能区分「行还在但密文已换」与「因子已被重置/删除」。
    assert!(
        repository::delete_totp_factor(&pool, user_id)
            .await
            .expect("delete TOTP factor")
    );
    assert_eq!(
        repository::update_totp_factor_if_current(&pool, user_id, &[9, 8, 7], &[5, 5, 5])
            .await
            .expect("CAS against deleted factor"),
        repository::TotpCasUpdateOutcome::Missing
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup test user");
}

#[tokio::test]
async fn passkey_first_factor_insert_rejects_repeat_and_cross_user_collisions() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_ids: Vec<i64> = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, status, created_at)
         VALUES ($1, $2, lower($2), 'test-hash', 'active', NOW()),
                ($3, $4, lower($4), 'test-hash', 'active', NOW())
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
        repository::insert_passkey_if_empty(&pool, user_ids[0], &credential_id, &passkey)
            .await
            .expect("insert passkey"),
        repository::PasskeyPersistenceResult::Stored
    );
    // 账号已有首因子，重复注册被 if_empty 守卫拒绝；行数不变，幂等性由数据库保证。
    assert_eq!(
        repository::insert_passkey_if_empty(&pool, user_ids[0], &credential_id, &passkey)
            .await
            .expect("repeat passkey insert"),
        repository::PasskeyPersistenceResult::Conflict
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
    // 另一个账号无首因子，但 credential_id 唯一约束触发 DO NOTHING，同样拒绝。
    assert_eq!(
        repository::insert_passkey_if_empty(&pool, user_ids[1], &credential_id, &passkey)
            .await
            .expect("cross-user collision result"),
        repository::PasskeyPersistenceResult::Conflict
    );
    assert!(
        repository::list_passkeys(&pool, user_ids[1])
            .await
            .expect("list second user passkeys")
            .is_empty(),
        "colliding credential must not be stored for the second user"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&user_ids)
        .execute(&pool)
        .await
        .expect("cleanup test users");
}

#[tokio::test]
async fn passkey_updates_use_row_id_user_and_version_cas() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple();
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, status, created_at)
         VALUES ($1, $2, lower($2), 'test-hash', 'active', NOW())
         RETURNING id",
    )
    .bind(format!("passkey-cas-{suffix}"))
    .bind(format!("passkey-cas-{suffix}@example.com"))
    .fetch_one(&pool)
    .await
    .expect("insert passkey CAS user");
    let credential_id = Uuid::new_v4().into_bytes().to_vec();
    let original = test_passkey_with_counter(&credential_id, 0);
    repository::insert_passkey_if_empty(&pool, user_id, &credential_id, &original)
        .await
        .expect("insert passkey");
    let stored = repository::list_passkeys_with_versions(&pool, user_id)
        .await
        .expect("load versioned passkey")
        .pop()
        .expect("stored passkey");
    let newer = test_passkey_with_counter(&credential_id, 2);
    let stale = test_passkey_with_counter(&credential_id, 1);
    assert_eq!(
        repository::update_passkey(
            &pool,
            user_id,
            stored.id,
            &credential_id,
            stored.state_version,
            &newer,
        )
        .await
        .expect("newer CAS update"),
        repository::PasskeyUpdateOutcome::Updated
    );
    assert_eq!(
        repository::update_passkey(
            &pool,
            user_id,
            stored.id,
            &credential_id,
            stored.state_version,
            &stale,
        )
        .await
        .expect("stale CAS update"),
        repository::PasskeyUpdateOutcome::Conflict
    );
    let persisted = repository::list_passkeys_with_versions(&pool, user_id)
        .await
        .expect("reload passkey")
        .pop()
        .expect("persisted passkey");
    assert_eq!(persisted.state_version, stored.state_version + 1);
    assert_eq!(
        serde_json::to_value(persisted.passkey()).expect("persisted JSON")["cred"]["counter"],
        serde_json::json!(2)
    );

    chenxing_auth::sqlx::query("DELETE FROM user_passkeys WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("delete original credential");
    // 重新注册用同一 credential_id 且 counter 仍是 0：旧实现按 cred_id+version
    // 会命中新行。CAS 必须按旧行 id 判定 Missing，不能改写新行。
    let replacement = test_passkey_with_counter(&credential_id, 0);
    repository::insert_passkey_if_empty(&pool, user_id, &credential_id, &replacement)
        .await
        .expect("re-register credential");
    let re_registered = repository::list_passkeys_with_versions(&pool, user_id)
        .await
        .expect("load re-registered passkey")
        .pop()
        .expect("re-registered passkey");
    assert_ne!(re_registered.id, stored.id);
    assert_eq!(
        repository::update_passkey(
            &pool,
            user_id,
            stored.id,
            &credential_id,
            stored.state_version,
            &stale,
        )
        .await
        .expect("stale update after re-registration"),
        repository::PasskeyUpdateOutcome::Missing
    );
    let after_stale = repository::list_passkeys_with_versions(&pool, user_id)
        .await
        .expect("reload after stale write")
        .pop()
        .expect("replacement still present");
    assert_eq!(after_stale.id, re_registered.id);
    assert_eq!(after_stale.state_version, re_registered.state_version);
    assert_eq!(
        serde_json::to_value(after_stale.passkey()).expect("replacement JSON")["cred"]["counter"],
        serde_json::json!(0)
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup passkey CAS user");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_factor_race_allows_only_one_factor_type_to_win() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple();
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, status, created_at)
         VALUES ($1, $2, lower($2), 'test-hash', 'active', NOW())
         RETURNING id",
    )
    .bind(format!("first-factor-{suffix}"))
    .bind(format!("first-factor-{suffix}@example.com"))
    .fetch_one(&pool)
    .await
    .expect("insert test user");
    let credential_id = Uuid::new_v4().into_bytes().to_vec();
    let passkey = test_passkey(&credential_id);

    let barrier = Arc::new(Barrier::new(3));
    let totp_barrier = Arc::clone(&barrier);
    let totp_pool = pool.clone();
    let totp_task = tokio::spawn(async move {
        totp_barrier.wait().await;
        repository::insert_totp_factor_if_empty(&totp_pool, user_id, &[1, 2, 3]).await
    });
    let passkey_barrier = Arc::clone(&barrier);
    let passkey_pool = pool.clone();
    let passkey_task = tokio::spawn(async move {
        passkey_barrier.wait().await;
        repository::insert_passkey_if_empty(&passkey_pool, user_id, &credential_id, &passkey).await
    });
    // Release both contenders together so this test exercises the database
    // uniqueness/first-factor boundary instead of merely testing call order.
    barrier.wait().await;

    let totp_result = totp_task
        .await
        .expect("join TOTP first-factor write")
        .expect("TOTP first-factor write");
    let passkey_result = passkey_task
        .await
        .expect("join Passkey first-factor write")
        .expect("Passkey first-factor write");
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

#[tokio::test]
async fn delete_passkeys_in_transaction_removes_all_credentials_for_one_user() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_ids: Vec<i64> = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, status, created_at)
         VALUES ($1, $2, lower($2), 'test-hash', 'active', NOW()),
                ($3, $4, lower($4), 'test-hash', 'active', NOW())
         RETURNING id",
    )
    .bind(format!("passkey-reset-{suffix}-a"))
    .bind(format!("passkey-reset-{suffix}-a@example.com"))
    .bind(format!("passkey-reset-{suffix}-b"))
    .bind(format!("passkey-reset-{suffix}-b@example.com"))
    .fetch_all(&pool)
    .await
    .expect("insert test users");

    for (index, user_id) in user_ids.iter().enumerate() {
        let credential_id = Uuid::new_v4().into_bytes().to_vec();
        let passkey = test_passkey(&credential_id);
        assert_eq!(
            repository::insert_passkey_if_empty(&pool, *user_id, &credential_id, &passkey)
                .await
                .expect("insert passkey"),
            repository::PasskeyPersistenceResult::Stored,
            "user {index} should store a first passkey"
        );
    }

    let mut transaction = pool.begin().await.expect("begin delete transaction");
    let removed = repository::delete_passkeys_in_transaction(&mut transaction, user_ids[0])
        .await
        .expect("delete first user passkeys");
    transaction.commit().await.expect("commit delete");
    assert_eq!(removed, 1);
    assert!(
        repository::list_passkeys(&pool, user_ids[0])
            .await
            .expect("list first user passkeys")
            .is_empty()
    );
    assert_eq!(
        repository::list_passkeys(&pool, user_ids[1])
            .await
            .expect("list second user passkeys")
            .len(),
        1,
        "deleting one user's passkeys must not touch another account"
    );

    let mut empty = pool.begin().await.expect("begin empty delete");
    let removed_again = repository::delete_passkeys_in_transaction(&mut empty, user_ids[0])
        .await
        .expect("repeat delete");
    empty.rollback().await.expect("rollback empty delete");
    assert_eq!(removed_again, 0);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&user_ids)
        .execute(&pool)
        .await
        .expect("cleanup test users");
}

#[tokio::test]
async fn authenticated_factor_inserts_require_active_user_and_exact_epoch() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_ids: Vec<i64> = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, status, created_at)
         VALUES ($1, $2, lower($2), 'test-hash', 'active', NOW()),
                ($3, $4, lower($4), 'test-hash', 'active', NOW())
         RETURNING id",
    )
    .bind(format!("authenticated-factor-{suffix}-a"))
    .bind(format!("authenticated-factor-{suffix}-a@example.com"))
    .bind(format!("authenticated-factor-{suffix}-b"))
    .bind(format!("authenticated-factor-{suffix}-b@example.com"))
    .fetch_all(&pool)
    .await
    .expect("insert authenticated factor users");

    assert_eq!(
        repository::insert_authenticated_totp_factor(&pool, user_ids[0], 0, &[1, 2, 3])
            .await
            .expect("authenticated TOTP insert"),
        repository::AuthenticatedTotpPersistenceResult::Stored
    );
    chenxing_auth::sqlx::query("UPDATE users SET session_epoch = 1 WHERE id = $1")
        .bind(user_ids[1])
        .execute(&pool)
        .await
        .expect("advance second user epoch");
    assert_eq!(
        repository::insert_authenticated_totp_factor(&pool, user_ids[1], 0, &[4, 5, 6])
            .await
            .expect("stale TOTP insert"),
        repository::AuthenticatedTotpPersistenceResult::AuthenticationChanged
    );
    assert!(
        repository::find_totp_secret(&pool, user_ids[1])
            .await
            .expect("stale TOTP lookup")
            .is_none()
    );

    let credential_id = Uuid::new_v4().into_bytes().to_vec();
    let passkey = test_passkey(&credential_id);
    assert_eq!(
        repository::insert_authenticated_passkey(&pool, user_ids[1], 1, &credential_id, &passkey,)
            .await
            .expect("authenticated Passkey insert"),
        repository::AuthenticatedPasskeyPersistenceResult::Stored
    );
    assert_eq!(
        repository::insert_authenticated_passkey(&pool, user_ids[0], 0, &credential_id, &passkey,)
            .await
            .expect("cross-user Passkey conflict"),
        repository::AuthenticatedPasskeyPersistenceResult::Conflict
    );

    chenxing_auth::sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
        .bind(user_ids[1])
        .execute(&pool)
        .await
        .expect("disable second user");
    let second_credential_id = Uuid::new_v4().into_bytes().to_vec();
    assert_eq!(
        repository::insert_authenticated_passkey(
            &pool,
            user_ids[1],
            1,
            &second_credential_id,
            &test_passkey(&second_credential_id),
        )
        .await
        .expect("disabled Passkey insert"),
        repository::AuthenticatedPasskeyPersistenceResult::AuthenticationChanged
    );
    assert_eq!(
        repository::list_passkeys(&pool, user_ids[1])
            .await
            .expect("disabled user Passkeys")
            .len(),
        1,
        "disabled or epoch-stale writes must not add another credential"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&user_ids)
        .execute(&pool)
        .await
        .expect("cleanup authenticated factor users");
}
