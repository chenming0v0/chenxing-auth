//! Issue #466: new sessions persist payload, row id, epoch, and outbox
//! atomically in a single `user_sessions` INSERT.
//!
//! Kept out of `integration_storage.rs` because that binary is already a
//! 3000-line monolith. These cases only need a user, a store, and the
//! encrypted payload shape.

#[path = "support/db_isolation.rs"]
mod db_isolation;

use std::{env, time::Duration};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use chenxing_auth::{
    sessions::{
        domain::{Session, session_token_hash_bytes},
        store::SessionStore,
    },
    users::{domain::ValidatedRegistration, email::EmailAddress, repository as user_repository},
};
use redis::AsyncCommands;
use uuid::Uuid;

const STORE_KEY: [u8; 32] = [0x42; 32];

fn email_address(raw: impl AsRef<str>) -> EmailAddress {
    let raw = raw.as_ref();
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("fixture email {raw:?}: {error}"))
}

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool_with_max_connections("session_payload_identity", &database_url, 4)
        .await
}

fn redis_client() -> redis::Client {
    let url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(url).expect("Redis URL")
}

async fn insert_user(pool: &chenxing_auth::sqlx::PgPool, label: &str) -> i64 {
    let suffix = Uuid::new_v4().simple().to_string();
    user_repository::insert_user(
        pool,
        ValidatedRegistration {
            username: format!("{label}-{suffix}"),
            email: email_address(format!("{label}-{suffix}@example.com")),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert session identity user")
    .id
}

fn decrypt_session_payload_json(encrypted: &[u8], key: [u8; 32]) -> serde_json::Value {
    assert!(encrypted.starts_with(b"CHX1"), "keyed payload header");
    let kid_length = u16::from_be_bytes(
        encrypted[4..6]
            .try_into()
            .expect("keyed payload kid length"),
    ) as usize;
    let nonce_start = 6 + kid_length;
    let nonce_end = nonce_start + 12;
    let cipher = Aes256Gcm::new_from_slice(&key).expect("session payload key");
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted[nonce_start..nonce_end]),
            &encrypted[nonce_end..],
        )
        .expect("decrypt session payload");
    serde_json::from_slice(&plaintext).expect("parse decrypted session payload")
}

fn encrypt_session_payload_json(payload: &serde_json::Value, key: [u8; 32]) -> Vec<u8> {
    let plaintext = serde_json::to_vec(payload).expect("serialize session payload");
    let cipher = Aes256Gcm::new_from_slice(&key).expect("session payload key");
    let nonce = [0x11; 12];
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .expect("encrypt session payload");
    let kid = b"legacy";
    let mut encrypted = Vec::with_capacity(4 + 2 + kid.len() + nonce.len() + ciphertext.len());
    encrypted.extend_from_slice(b"CHX1");
    encrypted.extend_from_slice(&(kid.len() as u16).to_be_bytes());
    encrypted.extend_from_slice(kid);
    encrypted.extend_from_slice(&nonce);
    encrypted.extend(ciphertext);
    encrypted
}

fn session_redis_key(token: &str) -> String {
    format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(session_token_hash_bytes(token))
    )
}

#[tokio::test]
async fn session_save_persists_one_identity_across_payload_row_and_outbox() {
    let pool = database().await;
    let user_id = insert_user(&pool, "session-payload-identity").await;
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), STORE_KEY);
    let mut session = Session::new(user_id.to_string(), Duration::from_secs(300)).expect("session");

    store
        .save(&mut session, Duration::from_secs(300))
        .await
        .expect("save session");

    let (row_id, encrypted_payload, generation): (i64, Vec<u8>, i64) =
        chenxing_auth::sqlx::query_as(
            "SELECT id, session_payload, session_epoch
             FROM user_sessions
             WHERE token_hash = $1",
        )
        .bind(session_token_hash_bytes(&session.token).to_vec())
        .fetch_one(&pool)
        .await
        .expect("read stored session payload");
    let payload = decrypt_session_payload_json(&encrypted_payload, STORE_KEY);
    assert_eq!(
        payload.get("id").and_then(serde_json::Value::as_i64),
        Some(row_id)
    );
    assert_eq!(row_id, session.id);
    assert!(
        payload.get("token").is_none(),
        "payload must not contain token"
    );
    assert!(
        !payload.to_string().contains(&session.token),
        "payload must not contain the plaintext session credential"
    );

    let outbox: (Option<i64>, i64) = chenxing_auth::sqlx::query_as(
        "SELECT session_id, generation
         FROM session_outbox
         WHERE operation = 'sync_session' AND session_id = $1",
    )
    .bind(row_id)
    .fetch_one(&pool)
    .await
    .expect("read session sync outbox");
    assert_eq!(outbox, (Some(row_id), generation));
}

#[tokio::test]
async fn concurrent_session_saves_keep_unique_ids_matched_to_each_payload() {
    let pool = database().await;
    let user_id = insert_user(&pool, "session-payload-concurrent").await;
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), STORE_KEY)
        .with_session_policy(Duration::from_secs(300), 16);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let mut session =
                Session::new(user_id.to_string(), Duration::from_secs(300)).expect("session");
            store
                .save(&mut session, Duration::from_secs(300))
                .await
                .expect("save concurrent session");
            session
        }));
    }

    let mut caller_ids = Vec::new();
    for task in tasks {
        caller_ids.push(task.await.expect("join concurrent session save").id);
    }
    caller_ids.sort_unstable();
    caller_ids.dedup();
    assert_eq!(caller_ids.len(), 8, "caller-visible ids must be unique");

    let rows: Vec<(i64, Vec<u8>)> = chenxing_auth::sqlx::query_as(
        "SELECT id, session_payload
         FROM user_sessions
         WHERE user_id = $1
         ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(&pool)
    .await
    .expect("read concurrent session payloads");
    assert_eq!(rows.len(), 8);
    let mut row_ids = Vec::with_capacity(rows.len());
    for (row_id, encrypted_payload) in rows {
        let payload = decrypt_session_payload_json(&encrypted_payload, STORE_KEY);
        assert_eq!(
            payload.get("id").and_then(serde_json::Value::as_i64),
            Some(row_id)
        );
        row_ids.push(row_id);
    }
    assert_eq!(row_ids, caller_ids);
}

#[tokio::test]
async fn session_save_failure_rolls_back_row_and_outbox_without_publishing_id() {
    let pool = database().await;
    let user_id = insert_user(&pool, "session-payload-rollback").await;
    chenxing_auth::sqlx::query(
        "ALTER TABLE session_outbox
         ADD CONSTRAINT reject_sync_session_for_rollback_test
         CHECK (operation <> 'sync_session')",
    )
    .execute(&pool)
    .await
    .expect("install outbox failure constraint");
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), STORE_KEY);
    let mut session = Session::new(user_id.to_string(), Duration::from_secs(300)).expect("session");
    let original_id = session.id;
    assert_eq!(original_id, 0);

    assert!(
        store
            .save(&mut session, Duration::from_secs(300))
            .await
            .is_err(),
        "forced outbox failure must reject the save"
    );
    assert_eq!(session.id, original_id);
    let session_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM user_sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("count rolled back sessions");
    let outbox_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM session_outbox WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("count rolled back outbox events");
    assert_eq!((session_count, outbox_count), (0, 0));
}

#[tokio::test]
async fn session_find_treats_legacy_zero_payload_id_as_row_id() {
    let pool = database().await;
    let user_id = insert_user(&pool, "session-payload-legacy-zero").await;
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), STORE_KEY);
    let mut session = Session::new(user_id.to_string(), Duration::from_secs(300)).expect("session");
    store
        .save(&mut session, Duration::from_secs(300))
        .await
        .expect("save session");

    let encrypted: Vec<u8> = chenxing_auth::sqlx::query_scalar(
        "SELECT session_payload FROM user_sessions WHERE id = $1",
    )
    .bind(session.id)
    .fetch_one(&pool)
    .await
    .expect("read stored payload");
    let mut payload = decrypt_session_payload_json(&encrypted, STORE_KEY);
    payload["id"] = serde_json::json!(0);
    let rewritten = encrypt_session_payload_json(&payload, STORE_KEY);
    chenxing_auth::sqlx::query("UPDATE user_sessions SET session_payload = $1 WHERE id = $2")
        .bind(&rewritten)
        .bind(session.id)
        .execute(&pool)
        .await
        .expect("write legacy zero payload");

    let found = store
        .find(&session.token)
        .await
        .expect("find")
        .expect("active session");
    assert_eq!(found.id, session.id);
    assert_ne!(found.id, 0);
}

#[tokio::test]
async fn session_outbox_projection_keeps_payload_id_aligned_with_row() {
    let pool = database().await;
    let user_id = insert_user(&pool, "session-payload-redis-id").await;
    let client = redis_client();
    let store = SessionStore::with_metadata_and_key(client.clone(), pool.clone(), STORE_KEY);
    let mut session = Session::new(user_id.to_string(), Duration::from_secs(300)).expect("session");
    store
        .save(&mut session, Duration::from_secs(300))
        .await
        .expect("save session");
    store
        .process_pending_outbox()
        .await
        .expect("project session payload");

    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let encrypted: Vec<u8> = connection
        .get(session_redis_key(&session.token))
        .await
        .expect("read Redis projection");
    let payload = decrypt_session_payload_json(&encrypted, STORE_KEY);
    assert_eq!(
        payload.get("id").and_then(serde_json::Value::as_i64),
        Some(session.id)
    );
    assert!(payload.get("token").is_none());
}
