//! Revocation writes stay database-authoritative before Redis delivery and outbox cleanup.

use super::*;

#[tokio::test]
async fn session_revoke_keeps_database_authoritative_until_redis_recovers() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-revoke-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-revoke-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox revoke user");
    let key = session_store_key();
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let revocation_marker = session_revocation_marker(user.id);
    let _: usize = connection
        .del(&revocation_marker)
        .await
        .expect("clear reused user revocation marker");
    let available = SessionStore::with_metadata_and_key(client, pool.clone(), key);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    available
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    available
        .process_pending_outbox()
        .await
        .expect("flush save outbox");

    let unavailable =
        SessionStore::with_metadata_and_key(unavailable_redis_client(), pool.clone(), key);
    unavailable
        .revoke(&session.token)
        .await
        .expect("database revoke must not depend on Redis availability");
    assert!(
        unavailable
            .find(&session.token)
            .await
            .expect("find revoked session")
            .is_none()
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_outbox
             WHERE operation = 'revoke_session' AND token_hash = $1 AND processed_at IS NULL",
        )
        .bind(sha2::Sha256::digest(session.token.as_bytes()).to_vec())
        .fetch_one(&pool)
        .await
        .expect("pending revoke outbox"),
        1
    );

    let redis_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
    assert!(
        connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("initial Redis session projection")
    );
    assert!(
        connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("stale Redis session")
    );
    available
        .process_pending_outbox()
        .await
        .expect("replay revoke outbox");
    assert!(
        !connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("revoked Redis session")
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox revoke user");
    let _: usize = connection
        .del(&revocation_marker)
        .await
        .expect("cleanup session revocation marker");
}

#[tokio::test]
async fn session_revoke_for_user_commits_revocation_before_redis_delivery() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-single-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-single-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox single revoke user");
    let key = session_store_key();
    let available = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), key);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    available
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    available
        .process_pending_outbox()
        .await
        .expect("flush save outbox");

    let unavailable =
        SessionStore::with_metadata_and_key(unavailable_redis_client(), pool.clone(), key);
    assert!(
        unavailable
            .revoke_for_user(user.id, session.id)
            .await
            .expect("database single revoke")
    );
    assert!(
        unavailable
            .find(&session.token)
            .await
            .expect("find revoked single session")
            .is_none()
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_outbox
             WHERE operation = 'revoke_session' AND session_id = $1 AND processed_at IS NULL",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("pending single revoke outbox"),
        1
    );
    available
        .process_pending_outbox()
        .await
        .expect("replay single revoke outbox");

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox single revoke user");
}

#[tokio::test]
async fn session_revoke_all_commits_all_rows_before_redis_delivery() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-all-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-all-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox all revoke user");
    let key = session_store_key();
    let available = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), key);
    let mut first =
        Session::new(user.id.to_string(), Duration::from_secs(60)).expect("first session");
    let mut second =
        Session::new(user.id.to_string(), Duration::from_secs(60)).expect("second session");
    available
        .save(&mut first, Duration::from_secs(60))
        .await
        .expect("save first session");
    available
        .save(&mut second, Duration::from_secs(60))
        .await
        .expect("save second session");
    available
        .process_pending_outbox()
        .await
        .expect("flush save outbox");

    let unavailable =
        SessionStore::with_metadata_and_key(unavailable_redis_client(), pool.clone(), key);
    unavailable
        .revoke_all_for_user(user.id)
        .await
        .expect("database batch revoke");
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_sessions
             WHERE user_id = $1 AND revoked_at IS NOT NULL",
        )
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .expect("revoked session metadata"),
        2
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_outbox
             WHERE operation = 'revoke_user' AND user_id = $1 AND processed_at IS NULL",
        )
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .expect("pending batch revoke outbox"),
        1
    );
    assert!(
        unavailable
            .find(&first.token)
            .await
            .expect("find first revoked session")
            .is_none()
    );
    assert!(
        unavailable
            .find(&second.token)
            .await
            .expect("find second revoked session")
            .is_none()
    );
    available
        .process_pending_outbox()
        .await
        .expect("replay batch revoke outbox");

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox all revoke user");
}

#[tokio::test]
async fn session_revoke_all_outbox_cleans_redis_after_user_deletion() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-delete-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-delete-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox deletion user");
    let key = session_store_key();
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let revocation_marker = session_revocation_marker(user.id);
    let _: usize = connection
        .del(&revocation_marker)
        .await
        .expect("clear reused user revocation marker");
    let available = SessionStore::with_metadata_and_key(client, pool.clone(), key);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    available
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    available
        .process_pending_outbox()
        .await
        .expect("flush save outbox");
    let redis_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
    assert!(
        connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("initial Redis session projection")
    );
    assert!(
        !connection
            .exists::<_, bool>(&revocation_marker)
            .await
            .expect("initial session revocation marker")
    );

    let unavailable =
        SessionStore::with_metadata_and_key(unavailable_redis_client(), pool.clone(), key);
    unavailable
        .revoke_all_for_user(user.id)
        .await
        .expect("database batch revoke");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("delete user with pending revoke outbox");

    assert!(
        connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("stale Redis session")
    );

    available
        .process_pending_outbox()
        .await
        .expect("replay deletion revoke outbox");
    let deleted = !connection
        .exists::<_, bool>(&redis_key)
        .await
        .expect("deleted Redis session");
    let _: usize = connection
        .del(&revocation_marker)
        .await
        .expect("cleanup session revocation marker");
    assert!(
        deleted,
        "pending revoke outbox must delete the Redis session projection"
    );
}
