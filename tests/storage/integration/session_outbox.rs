//! Session save/outbox durability and Redis fallback for active and terminal NULL payloads.

use super::*;

#[tokio::test]
async fn session_save_keeps_metadata_pending_when_redis_connection_fails() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-connection-failure-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "metadata-connection-failure-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert metadata connection failure user");

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve Redis port");
    let port = listener
        .local_addr()
        .expect("reserved Redis address")
        .port();
    drop(listener);
    let redis = redis::Client::open(format!("redis://127.0.0.1:{port}/")).expect("Redis URL");
    let sessions = SessionStore::with_metadata_and_key(redis, pool.clone(), [0x42; 32]);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");

    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("database save must not depend on Redis availability");
    assert!(
        session.id > 0,
        "database insert must happen before Redis access"
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_sessions WHERE id = $1",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("count durable session metadata"),
        1
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_outbox
             WHERE session_id = $1 AND operation = 'sync_session' AND processed_at IS NULL",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("count pending save outbox"),
        1
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup metadata connection failure user");
}

#[tokio::test]
async fn session_save_commits_metadata_and_replays_redis_after_connection_failure() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-save-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-save-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox save user");
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    let unavailable = SessionStore::with_metadata_and_key(
        unavailable_redis_client(),
        pool.clone(),
        session_store_key(),
    );

    unavailable
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("database save must not depend on Redis availability");
    assert!(
        unavailable
            .find(&session.token)
            .await
            .expect("find from PostgreSQL authority")
            .is_some()
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_outbox
             WHERE operation = 'sync_session' AND session_id = $1 AND processed_at IS NULL",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("pending save outbox"),
        1
    );
    assert_eq!(
        unavailable
            .process_pending_outbox()
            .await
            .expect("record failed Redis delivery"),
        0
    );
    let (attempts, has_error): (i32, bool) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, last_error IS NOT NULL
         FROM session_outbox
         WHERE operation = 'sync_session' AND session_id = $1 AND processed_at IS NULL",
    )
    .bind(session.id)
    .fetch_one(&pool)
    .await
    .expect("observable failed save outbox");
    assert_eq!(attempts, 1);
    assert!(has_error);
    chenxing_auth::sqlx::query(
        "UPDATE session_outbox SET available_at = NOW()
         WHERE operation = 'sync_session' AND session_id = $1 AND processed_at IS NULL",
    )
    .bind(session.id)
    .execute(&pool)
    .await
    .expect("make save outbox immediately retryable");

    let available =
        SessionStore::with_metadata_and_key(redis_client(), pool.clone(), session_store_key());
    assert!(
        available
            .process_pending_outbox()
            .await
            .expect("replay save outbox")
            > 0
    );
    assert!(
        available
            .find(&session.token)
            .await
            .expect("find replayed session")
            .is_some()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox save user");
}

/// Issue #314：升级期的 active + NULL 行仍以 Redis 作为唯一载荷来源。
#[tokio::test]
async fn session_sync_outbox_preserves_redis_fallback_for_active_null_payload() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-null-active-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-null-active-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert active NULL-payload user");
    let client = redis_client();
    let store =
        SessionStore::with_metadata_and_key(client.clone(), pool.clone(), session_store_key());
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(300)).expect("session");
    store
        .save(&mut session, Duration::from_secs(300))
        .await
        .expect("save active NULL-payload session");
    store
        .process_pending_outbox()
        .await
        .expect("project initial session payload");

    let redis_key = session_redis_key(&session.token);
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let fallback_payload: Vec<u8> = connection
        .get(&redis_key)
        .await
        .expect("initial Redis fallback payload");
    chenxing_auth::sqlx::query("UPDATE user_sessions SET session_payload = NULL WHERE id = $1")
        .bind(session.id)
        .execute(&pool)
        .await
        .expect("simulate pre-backfill session row");
    enqueue_session_sync(&pool, session.id).await;

    assert_eq!(
        store
            .process_pending_outbox()
            .await
            .expect("process active NULL-payload sync"),
        1
    );
    let retained_payload: Option<Vec<u8>> = connection
        .get(&redis_key)
        .await
        .expect("read retained Redis fallback payload");
    assert_eq!(
        retained_payload.as_deref(),
        Some(fallback_payload.as_slice())
    );
    assert!(
        store
            .find(&session.token)
            .await
            .expect("find session through Redis fallback")
            .is_some(),
        "an active migration row must not become a permanent 401"
    );

    let _: usize = connection
        .del(&redis_key)
        .await
        .expect("cleanup active NULL-payload Redis key");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup active NULL-payload user");
}

/// Issue #314：NULL 只代表载荷 fallback，不得覆盖 PostgreSQL 的终态判定。
#[tokio::test]
async fn session_sync_outbox_deletes_null_payload_fallbacks_after_revoke_or_expiry() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-null-terminal-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-null-terminal-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert terminal NULL-payload user");
    let client = redis_client();
    let store =
        SessionStore::with_metadata_and_key(client.clone(), pool.clone(), session_store_key());
    let mut revoked =
        Session::new(user.id.to_string(), Duration::from_secs(300)).expect("revoked session");
    let mut expired =
        Session::new(user.id.to_string(), Duration::from_secs(300)).expect("expired session");
    store
        .save(&mut revoked, Duration::from_secs(300))
        .await
        .expect("save session to revoke");
    store
        .save(&mut expired, Duration::from_secs(300))
        .await
        .expect("save session to expire");
    store
        .process_pending_outbox()
        .await
        .expect("project terminal-state fixtures");

    let revoked_key = session_redis_key(&revoked.token);
    let expired_key = session_redis_key(&expired.token);
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    assert!(
        connection
            .exists::<_, bool>(&revoked_key)
            .await
            .expect("revoked fixture projection")
    );
    assert!(
        connection
            .exists::<_, bool>(&expired_key)
            .await
            .expect("expired fixture projection")
    );

    chenxing_auth::sqlx::query(
        "UPDATE user_sessions
         SET session_payload = NULL, revoked_at = NOW()
         WHERE id = $1",
    )
    .bind(revoked.id)
    .execute(&pool)
    .await
    .expect("make NULL-payload session revoked");
    chenxing_auth::sqlx::query(
        "UPDATE user_sessions
         SET session_payload = NULL, expires_at = NOW() - INTERVAL '1 second'
         WHERE id = $1",
    )
    .bind(expired.id)
    .execute(&pool)
    .await
    .expect("make NULL-payload session expired");
    enqueue_session_sync(&pool, revoked.id).await;
    enqueue_session_sync(&pool, expired.id).await;

    assert_eq!(
        store
            .process_pending_outbox()
            .await
            .expect("process terminal NULL-payload syncs"),
        2
    );
    assert!(
        !connection
            .exists::<_, bool>(&revoked_key)
            .await
            .expect("revoked fallback deletion"),
        "revocation must win over the NULL-payload fallback"
    );
    assert!(
        !connection
            .exists::<_, bool>(&expired_key)
            .await
            .expect("expired fallback deletion"),
        "expiry must win over the NULL-payload fallback"
    );
    assert!(
        store
            .find(&revoked.token)
            .await
            .expect("find revoked NULL-payload session")
            .is_none()
    );
    assert!(
        store
            .find(&expired.token)
            .await
            .expect("find expired NULL-payload session")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup terminal NULL-payload user");
}
