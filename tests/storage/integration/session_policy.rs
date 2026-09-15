//! Session policy: active-session cap eviction and issuance-time idle window.

use super::*;

#[tokio::test]
async fn session_save_revokes_the_oldest_active_session_at_the_user_cap() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("session-cap-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "session-cap-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert session cap user");
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), [0x53; 32])
        .with_session_policy(Duration::from_secs(3_600), 2);
    let mut first = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(3_600),
        Duration::from_secs(3_600),
    )
    .expect("first session");
    store
        .save(&mut first, Duration::from_secs(3_600))
        .await
        .expect("save first session");
    let mut second = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(3_600),
        Duration::from_secs(3_600),
    )
    .expect("second session");
    store
        .save(&mut second, Duration::from_secs(3_600))
        .await
        .expect("save second session");
    let mut third = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(3_600),
        Duration::from_secs(3_600),
    )
    .expect("third session");
    store
        .save(&mut third, Duration::from_secs(3_600))
        .await
        .expect("save third session");

    let active_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_sessions
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .expect("count active session rows");
    assert_eq!(active_count, 2);
    assert!(
        store
            .find(&first.token)
            .await
            .expect("find evicted session")
            .is_none()
    );
    assert!(
        store
            .find(&second.token)
            .await
            .expect("find second")
            .is_some()
    );
    assert!(
        store
            .find(&third.token)
            .await
            .expect("find third")
            .is_some()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup session cap user");
}

/// #644: idle window is the value in force when the session was issued.
///
/// Changing the store policy afterwards must not keep a new session alive
/// under the old window, expire an already-issued session early, or ignore
/// a shortened window for sessions issued after the change.
#[tokio::test]
async fn session_idle_timeout_is_the_issuance_window_not_runtime_policy() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("idle-issued-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "idle-issued-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert issuance-idle user");
    let key = [0x64; 32];
    let client = redis_client();
    let runtime_policy = Arc::new(RwLock::new(SessionLifetimeSetting {
        session_ttl_seconds: 3_600,
        session_idle_timeout_seconds: 1_800,
    }));
    let store_boot = SessionStore::with_metadata_and_key(client.clone(), pool.clone(), key)
        .with_session_policy(Duration::from_secs(1_800), 5)
        .with_runtime_policy(runtime_policy.clone());
    let store_short = SessionStore::with_metadata_and_key(client.clone(), pool.clone(), key)
        .with_session_policy(Duration::from_secs(1_800), 5)
        .with_runtime_policy(runtime_policy.clone());

    let mut issued_under_boot = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(3_600),
        Duration::from_secs(1_800),
    )
    .expect("session issued under 1800s idle");
    store_boot
        .save(&mut issued_under_boot, Duration::from_secs(3_600))
        .await
        .expect("save 1800s session");
    let stored_idle: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT idle_timeout_seconds FROM user_sessions WHERE id = $1",
    )
    .bind(issued_under_boot.id)
    .fetch_one(&pool)
    .await
    .expect("read persisted idle window");
    assert_eq!(stored_idle, 1_800);

    // The runtime policy changes after issuance. The old row must continue to
    // use its own idle window for both token and hash-only lookup.
    runtime_policy
        .write()
        .expect("runtime policy lock")
        .session_idle_timeout_seconds = 60;

    chenxing_auth::sqlx::query(
        "UPDATE user_sessions
         SET last_seen_at = NOW() - INTERVAL '90 seconds'
         WHERE id = $1",
    )
    .bind(issued_under_boot.id)
    .execute(&pool)
    .await
    .expect("age 1800s session past a 60s policy");
    let found_old = store_short
        .find(&issued_under_boot.token)
        .await
        .expect("find session issued under 1800s")
        .expect("shortening the runtime policy must not expire an old session");
    assert!(
        found_old.is_active_at(OffsetDateTime::now_utc()),
        "old token lookup must retain the issuance-time idle window"
    );
    let old_hash = session_token_hash_bytes(&issued_under_boot.token);
    let found_old_hash = store_short
        .find_by_token_hash(&old_hash)
        .await
        .expect("hash-only lookup for old session")
        .expect("old hash-only lookup must remain active");
    assert!(
        found_old_hash.is_active_at(OffsetDateTime::now_utc()),
        "old hash-only lookup must retain the issuance-time idle window"
    );

    let new_idle = Duration::from_secs(
        runtime_policy
            .read()
            .expect("runtime policy read")
            .session_idle_timeout_seconds,
    );
    let mut issued_after_change =
        Session::new_with_idle_timeout(user.id.to_string(), Duration::from_secs(3_600), new_idle)
            .expect("session issued under 60s idle");
    store_short
        .save(&mut issued_after_change, Duration::from_secs(3_600))
        .await
        .expect("save 60s session");
    chenxing_auth::sqlx::query(
        "UPDATE user_sessions
         SET last_seen_at = NOW() - INTERVAL '90 seconds'
         WHERE id = $1",
    )
    .bind(issued_after_change.id)
    .execute(&pool)
    .await
    .expect("age 60s session past its own window");
    assert!(
        store_short
            .find(&issued_after_change.token)
            .await
            .expect("find session issued under 60s")
            .is_none(),
        "sessions issued after the admin change must use the new 60s window"
    );
    let new_hash = session_token_hash_bytes(&issued_after_change.token);
    assert!(
        store_short
            .find_by_token_hash(&new_hash)
            .await
            .expect("hash-only lookup for new session")
            .is_none(),
        "new hash-only lookup must use the new issuance-time window"
    );

    let mut issued_under_short = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(3_600),
        Duration::from_secs(60),
    )
    .expect("session issued under 60s idle before increase");
    store_short
        .save(&mut issued_under_short, Duration::from_secs(3_600))
        .await
        .expect("save short-lived session");
    chenxing_auth::sqlx::query(
        "UPDATE user_sessions
         SET last_seen_at = NOW() - INTERVAL '90 seconds'
         WHERE id = $1",
    )
    .bind(issued_under_short.id)
    .execute(&pool)
    .await
    .expect("age short-lived session");
    assert!(
        store_boot
            .find(&issued_under_short.token)
            .await
            .expect("find short-lived session under a longer store policy")
            .is_none(),
        "increasing the store policy must not keep already-issued sessions alive"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup issuance-idle user");
}
