//! Session lookup semantics: issuance idle window, revocation generation and database identity.

use super::*;

/// Issue #673: Redis must keep the issuance-time idle field in its payload.
/// Both token and hash-only lookup must survive a later runtime policy change
/// for old sessions, while sessions issued after the change use the new value.
#[tokio::test]
async fn redis_session_lookup_preserves_issuance_idle_after_runtime_change() {
    let runtime_policy = Arc::new(RwLock::new(SessionLifetimeSetting {
        session_ttl_seconds: 3_600,
        session_idle_timeout_seconds: 1_800,
    }));
    let store = SessionStore::with_redis_key(redis_client(), [0x65; 32])
        .with_session_policy(Duration::from_secs(1_800), 5)
        .with_runtime_policy(runtime_policy.clone());
    let now = OffsetDateTime::now_utc();

    let mut old_session = Session::new_at_with_idle_timeout(
        "redis-issue-673-old".to_owned(),
        Duration::from_secs(3_600),
        Duration::from_secs(1_800),
        now - time::Duration::seconds(90),
    )
    .expect("old Redis session");
    store
        .save(&mut old_session, Duration::from_secs(3_600))
        .await
        .expect("save old Redis session");

    runtime_policy
        .write()
        .expect("runtime policy lock")
        .session_idle_timeout_seconds = 60;

    let found_old = store
        .find(&old_session.token)
        .await
        .expect("find old Redis session")
        .expect("old Redis session remains active");
    assert!(found_old.is_active_at(now));
    let old_hash = session_token_hash_bytes(&old_session.token);
    let found_old_hash = store
        .find_by_token_hash(&old_hash)
        .await
        .expect("hash-only lookup for old Redis session")
        .expect("old Redis hash-only session remains active");
    assert!(found_old_hash.is_active_at(now));

    let new_idle = Duration::from_secs(
        runtime_policy
            .read()
            .expect("runtime policy read")
            .session_idle_timeout_seconds,
    );
    let mut new_session = Session::new_at_with_idle_timeout(
        "redis-issue-673-new".to_owned(),
        Duration::from_secs(3_600),
        new_idle,
        now - time::Duration::seconds(90),
    )
    .expect("new Redis session");
    store
        .save(&mut new_session, Duration::from_secs(3_600))
        .await
        .expect("save new Redis session");
    assert!(
        store
            .find(&new_session.token)
            .await
            .expect("find new Redis session")
            .is_none()
    );
    let new_hash = session_token_hash_bytes(&new_session.token);
    assert!(
        store
            .find_by_token_hash(&new_hash)
            .await
            .expect("hash-only lookup for new Redis session")
            .is_none()
    );
}

#[tokio::test]
async fn session_revocation_generation_rejects_restored_old_payloads() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("generation-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "generation-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert generation user");
    let client = redis_client();
    let sessions = SessionStore::with_metadata_and_key(client.clone(), pool.clone(), [0x42; 32]);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    sessions
        .revoke_all_for_user(user.id)
        .await
        .expect("revoke all sessions");

    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: () = connection
        .set_ex(
            format!(
                "chenxing:session:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(session.token.as_bytes()))
            ),
            serde_json::to_string(&chenxing_auth::sessions::domain::SessionPayload::from(
                &session,
            ))
            .expect("session JSON"),
            60,
        )
        .await
        .expect("restore old payload");
    assert!(
        sessions
            .find(&session.token)
            .await
            .expect("find restored session")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup generation user");
}

#[tokio::test]
async fn session_find_rejects_metadata_revocation_even_when_redis_payload_exists() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-revoke-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "metadata-revoke-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert metadata revoke user");
    let client = redis_client();
    let sessions = SessionStore::with_metadata_and_key(client, pool.clone(), [0x42; 32]);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    chenxing_auth::sqlx::query("UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1")
        .bind(session.id)
        .execute(&pool)
        .await
        .expect("revoke session metadata");

    assert!(
        sessions
            .find(&session.token)
            .await
            .expect("find revoked metadata session")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup metadata revoke user");
}

#[tokio::test]
async fn session_find_uses_database_identity_for_cached_payloads() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-identity-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "metadata-identity-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert metadata identity user");
    let other = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-other-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "metadata-other-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert metadata other user");
    let client = redis_client();
    let sessions = SessionStore::with_metadata_and_key(client, pool.clone(), [0x42; 32]);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    session.user_id = other.id.to_string();

    let found = sessions
        .find(&session.token)
        .await
        .expect("find cached session")
        .expect("cached session remains valid");
    assert_eq!(found.user_id, user.id.to_string());

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id IN ($1, $2)")
        .bind(user.id)
        .bind(other.id)
        .execute(&pool)
        .await
        .expect("cleanup metadata identity users");
}
