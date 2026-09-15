//! Encrypted session projection with a rotating encryption key ring.

use super::*;

#[tokio::test]
async fn session_projection_is_encrypted_and_old_key_remains_readable() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("key-ring-{}", Uuid::new_v4().simple()),
            email: email_address(format!("key-ring-{}@example.com", Uuid::new_v4().simple())),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert key ring user");
    let client = redis_client();
    let old_store = SessionStore::with_metadata_and_key(client.clone(), pool.clone(), [2; 32]);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    old_store
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save old-key session");

    let ring = AuthEncryptionKeyRing::from_entries(
        "current".to_owned(),
        vec![
            ("current".to_owned(), AuthEncryptionKey::new([1; 32])),
            ("previous".to_owned(), AuthEncryptionKey::new([2; 32])),
        ],
    )
    .expect("rotation ring");
    let rotated = SessionStore::with_metadata_and_key_ring(client.clone(), pool.clone(), ring);
    assert!(
        rotated
            .find(&session.token)
            .await
            .expect("read old key")
            .is_some()
    );
    rotated
        .process_pending_outbox()
        .await
        .expect("project encrypted session");

    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let redis_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
    let projected: Vec<u8> = connection.get(&redis_key).await.expect("projected payload");
    assert!(
        !projected
            .windows(session.token.len())
            .any(|window| window == session.token.as_bytes())
    );
    assert!(
        !projected
            .windows(session.csrf_token.len())
            .any(|window| window == session.csrf_token.as_bytes())
    );

    let invalid_key = SessionStore::with_metadata_and_key(client, pool.clone(), [3; 32]);
    assert!(
        invalid_key
            .find(&session.token)
            .await
            .expect("invalid key must be controlled")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup key ring user");
}
