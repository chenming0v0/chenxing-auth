//! Outbox claiming window and sync projection racing a concurrent revocation.

use super::*;

#[tokio::test]
async fn session_outbox_claims_new_events_but_not_future_events() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-clock-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-clock-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox clock user");
    let store =
        SessionStore::with_metadata_and_key(redis_client(), pool.clone(), session_store_key());

    let mut immediate =
        Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    store
        .save(&mut immediate, Duration::from_secs(60))
        .await
        .expect("save immediate session");
    store
        .process_pending_outbox()
        .await
        .expect("claim immediate outbox event");
    let (attempts, processed): (i32, bool) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, processed_at IS NOT NULL
         FROM session_outbox
         WHERE session_id = $1 AND operation = 'sync_session'",
    )
    .bind(immediate.id)
    .fetch_one(&pool)
    .await
    .expect("observe immediate outbox event");
    assert_eq!(attempts, 1);
    assert!(processed);

    let mut future = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    store
        .save(&mut future, Duration::from_secs(60))
        .await
        .expect("save future session");
    chenxing_auth::sqlx::query(
        "UPDATE session_outbox
         SET available_at = NOW() + INTERVAL '1 hour'
         WHERE session_id = $1 AND operation = 'sync_session' AND processed_at IS NULL",
    )
    .bind(future.id)
    .execute(&pool)
    .await
    .expect("delay future outbox event");

    store
        .process_pending_outbox()
        .await
        .expect("skip future outbox event");
    let (attempts, processed): (i32, bool) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, processed_at IS NOT NULL
         FROM session_outbox
         WHERE session_id = $1 AND operation = 'sync_session'",
    )
    .bind(future.id)
    .fetch_one(&pool)
    .await
    .expect("observe future outbox event");
    assert_eq!(attempts, 0);
    assert!(!processed);

    chenxing_auth::sqlx::query(
        "UPDATE session_outbox SET available_at = NOW()
         WHERE session_id = $1 AND operation = 'sync_session' AND processed_at IS NULL",
    )
    .bind(future.id)
    .execute(&pool)
    .await
    .expect("release future outbox event");
    store
        .process_pending_outbox()
        .await
        .expect("claim released outbox event");
    let (attempts, processed): (i32, bool) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, processed_at IS NOT NULL
         FROM session_outbox
         WHERE session_id = $1 AND operation = 'sync_session'",
    )
    .bind(future.id)
    .fetch_one(&pool)
    .await
    .expect("observe released outbox event");
    assert_eq!(attempts, 1);
    assert!(processed);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox clock user");
}

#[tokio::test]
async fn session_sync_projection_does_not_resurrect_a_concurrently_revoked_row() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-race-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-race-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox race user");
    let available =
        SessionStore::with_metadata_and_key(redis_client(), pool.clone(), session_store_key());
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    available
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");

    let mut lock = pool.begin().await.expect("session row lock transaction");
    chenxing_auth::sqlx::query("SELECT id FROM user_sessions WHERE id = $1 FOR UPDATE")
        .bind(session.id)
        .fetch_one(&mut *lock)
        .await
        .expect("lock session row");
    let worker = tokio::spawn({
        let available = available.clone();
        async move { available.process_pending_outbox().await }
    });
    for _ in 0..50 {
        let attempts: i32 = chenxing_auth::sqlx::query_scalar(
            "SELECT attempts FROM session_outbox WHERE session_id = $1 AND operation = 'sync_session'",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("observe claimed sync outbox");
        if attempts > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    chenxing_auth::sqlx::query("UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1")
        .bind(session.id)
        .execute(&mut *lock)
        .await
        .expect("revoke locked session row");
    lock.commit().await.expect("commit concurrent revocation");
    worker
        .await
        .expect("join projection worker")
        .expect("process projection outbox");

    let mut connection = redis_client()
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let redis_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
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
        .expect("cleanup outbox race user");
}
