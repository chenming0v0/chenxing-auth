//! Concurrent save and revoke-all keep the session epoch boundary monotonic.

use super::*;

#[tokio::test]
async fn concurrent_save_and_revoke_all_keep_the_epoch_boundary_monotonic() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("epoch-race-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "epoch-race-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert epoch race user");
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), [0x42; 32]);
    let mut concurrent =
        Session::new(user.id.to_string(), Duration::from_secs(60)).expect("concurrent session");

    let (save_result, revoke_result) = tokio::join!(
        store.save(&mut concurrent, Duration::from_secs(60)),
        store.revoke_all_for_user(user.id),
    );
    save_result.expect("concurrent save");
    revoke_result.expect("concurrent revoke all");

    let sync_id: Option<(i64,)> = chenxing_auth::sqlx::query_as(
        "SELECT id FROM session_outbox
         WHERE session_id = $1 AND operation = 'sync_session'
         ORDER BY id DESC LIMIT 1",
    )
    .bind(concurrent.id)
    .fetch_optional(&pool)
    .await
    .expect("find concurrent sync event");
    if let Some((sync_id,)) = sync_id {
        chenxing_auth::sqlx::query(
            "UPDATE session_outbox
             SET available_at = NOW() + INTERVAL '1 hour'
             WHERE id = $1",
        )
        .bind(sync_id)
        .execute(&pool)
        .await
        .expect("delay sync event");
    }
    store
        .process_pending_outbox()
        .await
        .expect("apply revoke events first");
    if let Some((sync_id,)) = sync_id {
        chenxing_auth::sqlx::query("UPDATE session_outbox SET available_at = NOW() WHERE id = $1")
            .bind(sync_id)
            .execute(&pool)
            .await
            .expect("release delayed sync event");
        store
            .process_pending_outbox()
            .await
            .expect("apply delayed sync event");
    }

    let state: Option<(bool, i64, i64)> = chenxing_auth::sqlx::query_as(
        "SELECT sessions.revoked_at IS NULL, sessions.session_epoch, users.session_epoch
         FROM user_sessions AS sessions
         JOIN users ON users.id = sessions.user_id
         WHERE sessions.id = $1",
    )
    .bind(concurrent.id)
    .fetch_optional(&pool)
    .await
    .expect("read concurrent session state");
    let Some((active, session_epoch, user_epoch)) = state else {
        panic!("concurrent session row missing");
    };
    if active {
        assert!(session_epoch >= user_epoch);
        assert!(
            store
                .find(&concurrent.token)
                .await
                .expect("find current session")
                .is_some()
        );
    } else {
        assert!(
            store
                .find(&concurrent.token)
                .await
                .expect("find revoked session")
                .is_none()
        );
    }

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup epoch race user");
}
