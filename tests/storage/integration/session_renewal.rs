//! Idle-activity renewal, foreign row-lock behaviour and renewal racing a revocation.

use super::*;

#[tokio::test]
async fn session_find_renews_idle_activity_without_extending_absolute_expiry() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("idle-renew-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "idle-renew-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert idle renewal user");
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), [0x52; 32])
        .with_session_policy(Duration::from_secs(10), 5);
    let mut session = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(300),
        Duration::from_secs(10),
    )
    .expect("session");
    let absolute_expiry = session.expires_at;
    store
        .save(&mut session, Duration::from_secs(300))
        .await
        .expect("save idle renewal session");
    chenxing_auth::sqlx::query(
        "UPDATE user_sessions
         SET last_seen_at = NOW() - INTERVAL '6 seconds'
         WHERE id = $1",
    )
    .bind(session.id)
    .execute(&pool)
    .await
    .expect("age session activity");

    let found = store
        .find(&session.token)
        .await
        .expect("find renewed session")
        .expect("renewed session remains active");
    let expiry_difference_nanos = found
        .expires_at
        .unix_timestamp_nanos()
        .abs_diff(absolute_expiry.unix_timestamp_nanos());
    assert!(
        expiry_difference_nanos < 1_000,
        "absolute expiry changed by {expiry_difference_nanos}ns"
    );
    assert!(found.last_seen_at > session.created_at);
    let stored_last_seen: OffsetDateTime =
        chenxing_auth::sqlx::query_scalar("SELECT last_seen_at FROM user_sessions WHERE id = $1")
            .bind(session.id)
            .fetch_one(&pool)
            .await
            .expect("read renewed activity");
    assert!(stored_last_seen > session.created_at);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup idle renewal user");
}

/// Issue #432: non-renewing find must not take `FOR UPDATE`, so a concurrent
/// holder of the session row lock cannot stall authentication — including the
/// Redis payload fallback path that used to run inside the locked transaction.
#[tokio::test]
async fn session_find_does_not_block_on_foreign_row_lock() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("find-nolock-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "find-nolock-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert find-nolock user");
    let client = redis_client();
    let store =
        SessionStore::with_metadata_and_key(client.clone(), pool.clone(), session_store_key());
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(300)).expect("session");
    store
        .save(&mut session, Duration::from_secs(300))
        .await
        .expect("save session");
    store
        .process_pending_outbox()
        .await
        .expect("project session payload");

    // Force the legacy Redis fallback so the regression covers external I/O,
    // not only the Postgres-payload hot path.
    chenxing_auth::sqlx::query("UPDATE user_sessions SET session_payload = NULL WHERE id = $1")
        .bind(session.id)
        .execute(&pool)
        .await
        .expect("clear durable payload");
    assert!(
        client
            .get_multiplexed_async_connection()
            .await
            .expect("redis")
            .exists::<_, bool>(session_redis_key(&session.token))
            .await
            .expect("redis key present"),
        "fallback requires a live Redis projection"
    );

    let mut lock = pool.begin().await.expect("foreign lock transaction");
    chenxing_auth::sqlx::query("SELECT id FROM user_sessions WHERE id = $1 FOR UPDATE")
        .bind(session.id)
        .fetch_one(&mut *lock)
        .await
        .expect("hold session row lock");

    let found = tokio::time::timeout(Duration::from_secs(2), store.find(&session.token))
        .await
        .expect("find must not wait on an unrelated FOR UPDATE holder")
        .expect("find under foreign lock")
        .expect("active session remains visible without taking the row lock");
    assert_eq!(found.id, session.id);
    assert_eq!(found.user_id, user.id.to_string());

    lock.commit().await.expect("release foreign lock");

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup find-nolock user");
}

/// Issue #432: renewal still serializes on the row lock, but only after payload
/// resolution — a concurrent revoker that commits under the lock must win, and
/// find must not return the session after losing that race.
#[tokio::test]
async fn session_find_renewal_observes_concurrent_revocation() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("find-renew-race-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "find-renew-race-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert find-renew-race user");
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), [0x53; 32])
        .with_session_policy(Duration::from_secs(10), 5);
    let mut session = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(300),
        Duration::from_secs(10),
    )
    .expect("session");
    store
        .save(&mut session, Duration::from_secs(300))
        .await
        .expect("save session");
    chenxing_auth::sqlx::query(
        "UPDATE user_sessions
         SET last_seen_at = NOW() - INTERVAL '6 seconds'
         WHERE id = $1",
    )
    .bind(session.id)
    .execute(&pool)
    .await
    .expect("age session into the renewal window");

    let mut lock = pool.begin().await.expect("revocation lock transaction");
    chenxing_auth::sqlx::query("SELECT id FROM user_sessions WHERE id = $1 FOR UPDATE")
        .bind(session.id)
        .fetch_one(&mut *lock)
        .await
        .expect("lock session before concurrent find");

    let find = tokio::spawn({
        let store = store.clone();
        let token = session.token.clone();
        async move { store.find(&token).await }
    });
    // Give the finder time to finish the unlocked read and block on renewal.
    tokio::time::sleep(Duration::from_millis(100)).await;
    chenxing_auth::sqlx::query("UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1")
        .bind(session.id)
        .execute(&mut *lock)
        .await
        .expect("revoke under lock");
    lock.commit().await.expect("commit concurrent revocation");

    let found = find
        .await
        .expect("join finder")
        .expect("find after concurrent revoke");
    assert!(
        found.is_none(),
        "renewal must re-check under FOR UPDATE and fail closed after revoke"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup find-renew-race user");
}
