use std::{env, time::Duration};

use base64::Engine;
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{
    clients::{domain::ValidatedClientRegistration, repository as client_repository},
    db,
    oauth::{
        code::AuthorizationCode, refresh::RefreshToken, refresh_store::RefreshTokenStore,
        store::AuthorizationCodeStore,
    },
    sessions::{domain::Session, store::SessionStore},
    users::{
        credentials::hash_password,
        domain::ValidatedRegistration,
        repository::{self as user_repository, NewUser},
    },
};
use redis::AsyncCommands;
use serial_test::serial;
use sha2::Digest;
use time::OffsetDateTime;
use uuid::Uuid;

async fn database() -> chenxing_auth::sqlx::PgPool {
    let url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("PostgreSQL is required for integration storage tests");
    db::migrate(&pool).await.expect("database migrations");
    pool
}

fn redis_client() -> redis::Client {
    let url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(url).expect("Redis URL")
}

#[tokio::test]
async fn postgres_repositories_round_trip_users_and_clients() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("storage-{suffix}@example.com");
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("storage-user-{suffix}"),
            email: email.clone(),
            password: "correct horse battery".to_owned(),
            display_name: Some("Storage User".to_owned()),
        },
        hash_password("correct horse battery").expect("password hash"),
    )
    .await
    .expect("insert user");

    let credentials = user_repository::find_credentials_by_email(&pool, &email)
        .await
        .expect("find credentials")
        .expect("stored credentials");
    assert_eq!(credentials.id, user.id);
    let profile = user_repository::find_profile_by_id(&pool, user.id)
        .await
        .expect("find profile")
        .expect("stored profile");
    assert_eq!(profile.display_name.as_deref(), Some("Storage User"));
    assert!(
        user_repository::find_profile_by_id(&pool, -1)
            .await
            .expect("find missing profile")
            .is_none()
    );

    let client_id = format!("storage-client-{suffix}");
    let client = client_repository::insert_client(
        &pool,
        ValidatedClientRegistration {
            client_name: "Storage Client".to_owned(),
            redirect_uris: vec!["https://storage.example/callback".to_owned()],
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
        },
        client_id.clone(),
        "client-secret-hash".to_owned(),
    )
    .await
    .expect("insert client");
    let stored = client_repository::find_client_by_id(&pool, &client_id)
        .await
        .expect("find client")
        .expect("stored client");
    assert_eq!(stored.redirect_uris.len(), 1);
    let credentials = client_repository::find_client_credentials(&pool, &client_id)
        .await
        .expect("find client credentials")
        .expect("stored client credentials");
    assert_eq!(credentials.client_secret_hash, "client-secret-hash");
    assert!(
        !client_repository::list_clients(&pool)
            .await
            .expect("list clients")
            .is_empty()
    );
    assert!(
        client_repository::update_client(
            &pool,
            &client_id,
            "Updated Client",
            &["https://storage.example/new-callback".to_owned()],
            &["openid".to_owned()],
        )
        .await
        .expect("update client")
    );
    assert!(
        client_repository::set_client_status(&pool, &client_id, "disabled")
            .await
            .expect("disable client")
    );
    assert!(
        client_repository::update_client_secret(&pool, &client_id, "new-hash")
            .await
            .expect("update client secret")
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
        .bind(client.id)
        .execute(&pool)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup user");
}

#[tokio::test]
async fn postgres_transaction_user_insert_and_missing_client_paths_work() {
    let pool = database().await;
    let user = NewUser {
        id: 0,
        username: format!("transaction-user-{}", Uuid::new_v4().simple()),
        email: format!("transaction-{}@example.com", Uuid::new_v4().simple()),
        password_hash: "hash".to_owned(),
        display_name: None,
        created_at: OffsetDateTime::now_utc(),
    };
    let mut transaction = pool.begin().await.expect("begin transaction");
    let user_id = user_repository::insert_user_in_transaction(&mut transaction, &user)
        .await
        .expect("insert user in transaction");
    transaction.commit().await.expect("commit transaction");
    assert!(
        client_repository::find_client_by_id(&pool, "missing-client")
            .await
            .expect("find missing client")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup transaction user");
}

#[tokio::test]
async fn owned_clients_are_isolated_and_limited_to_two_projects() {
    let pool = database().await;
    let owner = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("owner-{}", Uuid::new_v4().simple()),
            email: format!("owner-{}@example.com", Uuid::new_v4().simple()),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert owner");
    let other = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("other-{}", Uuid::new_v4().simple()),
            email: format!("other-{}@example.com", Uuid::new_v4().simple()),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert other owner");

    let registration = || ValidatedClientRegistration {
        client_name: "Owned Client".to_owned(),
        redirect_uris: vec!["https://owned.example/callback".to_owned()],
        scopes: vec!["openid".to_owned()],
    };
    client_repository::insert_owned_client(
        &pool,
        owner.id,
        registration(),
        format!("owned-client-first-{}", Uuid::new_v4().simple()),
        "hash".to_owned(),
        2,
    )
    .await
    .expect("insert first owned client");
    let (concurrent_a, concurrent_b) = tokio::join!(
        client_repository::insert_owned_client(
            &pool,
            owner.id,
            registration(),
            format!("owned-client-a-{}", Uuid::new_v4().simple()),
            "hash".to_owned(),
            2,
        ),
        client_repository::insert_owned_client(
            &pool,
            owner.id,
            registration(),
            format!("owned-client-b-{}", Uuid::new_v4().simple()),
            "hash".to_owned(),
            2,
        ),
    );
    let concurrent_results = [concurrent_a, concurrent_b];
    assert_eq!(
        concurrent_results
            .iter()
            .filter(|result| result.is_ok())
            .count(),
        1
    );
    assert_eq!(
        concurrent_results
            .iter()
            .filter(|result| matches!(
                result,
                Err(client_repository::ClientInsertError::QuotaExceeded)
            ))
            .count(),
        1
    );
    assert_eq!(
        client_repository::list_clients_for_owner(&pool, owner.id)
            .await
            .expect("list owner clients")
            .len(),
        2
    );
    assert!(
        client_repository::list_clients_for_owner(&pool, other.id)
            .await
            .expect("list other clients")
            .is_empty()
    );
    assert!(matches!(
        client_repository::insert_owned_client(
            &pool,
            owner.id,
            registration(),
            format!("owned-client-third-{}", Uuid::new_v4().simple()),
            "hash".to_owned(),
            2,
        )
        .await,
        Err(client_repository::ClientInsertError::QuotaExceeded)
    ));

    let orphan_owner = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("orphan-{}", Uuid::new_v4().simple()),
            email: format!("orphan-{}@example.com", Uuid::new_v4().simple()),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert orphan owner");
    let orphan_client = client_repository::insert_owned_client(
        &pool,
        orphan_owner.id,
        registration(),
        format!("orphan-client-{}", Uuid::new_v4().simple()),
        "hash".to_owned(),
        2,
    )
    .await
    .expect("insert orphan client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(orphan_owner.id)
        .execute(&pool)
        .await
        .expect("delete owner");
    assert!(
        client_repository::find_client_by_id(&pool, &orphan_client.client_id)
            .await
            .expect("find deleted client")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id IN ($1, $2)")
        .bind(owner.id)
        .bind(other.id)
        .execute(&pool)
        .await
        .expect("cleanup owned clients and users");
}

#[tokio::test]
async fn redis_stores_cover_session_and_one_time_token_lifecycles() {
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");

    let sessions = SessionStore::new(client.clone());
    let mut session =
        Session::new("storage-user".to_owned(), Duration::from_secs(60)).expect("session");
    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    assert_eq!(
        sessions
            .find(&session.token)
            .await
            .expect("find session")
            .unwrap()
            .id,
        session.id
    );
    sessions
        .revoke(&session.token)
        .await
        .expect("revoke session");
    assert!(
        sessions
            .find(&session.token)
            .await
            .expect("find revoked session")
            .is_none()
    );

    let codes = AuthorizationCodeStore::new(client.clone());
    let code = AuthorizationCode::new(
        "storage-client".to_owned(),
        "https://storage.example/callback".to_owned(),
        "storage-user".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
    );
    codes.save(&code).await.expect("save authorization code");
    assert!(codes.find(&code.value).await.expect("find code").is_some());
    let mismatched = AuthorizationCode::new(
        code.client_id.clone(),
        code.redirect_uri.clone(),
        code.user_id.clone(),
        code.scopes.clone(),
        "different-challenge".to_owned(),
    );
    assert!(
        !codes
            .take_if_matches(&code.value, &mismatched)
            .await
            .expect("mismatched code consume")
    );
    assert!(
        codes
            .take_if_matches(&code.value, &code)
            .await
            .expect("matching code consume")
    );
    assert!(
        codes
            .take(&code.value)
            .await
            .expect("take missing code")
            .is_none()
    );
    codes
        .restore(&code, 60)
        .await
        .expect("restore authorization code");
    assert_eq!(
        codes
            .find(&code.value)
            .await
            .expect("find restored code")
            .expect("restored authorization code")
            .value,
        code.value
    );
    codes.take(&code.value).await.expect("remove restored code");

    let refreshes = RefreshTokenStore::new(client);
    let refresh = RefreshToken::new(
        "storage-client".to_owned(),
        "storage-user".to_owned(),
        vec!["openid".to_owned()],
    );
    refreshes.save(&refresh).await.expect("save refresh token");
    assert!(
        refreshes
            .find(&refresh.value)
            .await
            .expect("find refresh")
            .is_some()
    );
    assert!(
        refreshes
            .take_if_matches(&refresh.value, &refresh)
            .await
            .expect("consume refresh token")
    );
    assert!(
        refreshes
            .take(&refresh.value)
            .await
            .expect("take missing refresh")
            .is_none()
    );

    let rotatable = RefreshToken::new(
        "storage-client".to_owned(),
        "storage-user".to_owned(),
        vec!["openid".to_owned()],
    );
    let rotated = RefreshToken::new(
        rotatable.client_id.clone(),
        rotatable.user_id.clone(),
        rotatable.scopes.clone(),
    );
    let mismatched = RefreshToken::new(
        rotatable.client_id.clone(),
        rotatable.user_id.clone(),
        vec!["profile".to_owned()],
    );
    refreshes
        .save(&rotatable)
        .await
        .expect("save rotatable refresh token");
    assert!(
        !refreshes
            .rotate_if_matches(&rotatable.value, &mismatched, &rotated)
            .await
            .expect("mismatched refresh rotation")
    );
    assert!(
        refreshes
            .find(&rotatable.value)
            .await
            .expect("find refresh after mismatched rotation")
            .is_some()
    );
    assert!(
        refreshes
            .rotate_if_matches(&rotatable.value, &rotatable, &rotated)
            .await
            .expect("matching refresh rotation")
    );
    assert!(
        refreshes
            .find(&rotatable.value)
            .await
            .expect("find consumed refresh")
            .is_none()
    );
    assert!(
        refreshes
            .find(&rotated.value)
            .await
            .expect("find rotated refresh")
            .is_some()
    );
    assert!(
        !refreshes
            .rotate_if_matches(
                &rotatable.value,
                &rotatable,
                &RefreshToken::new(
                    rotatable.client_id.clone(),
                    rotatable.user_id.clone(),
                    rotatable.scopes.clone(),
                )
            )
            .await
            .expect("duplicate refresh rotation")
    );

    let session_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
    let _: usize = connection
        .del(&[
            session_key,
            format!("chenxing:oauth:code:{}", code.value),
            format!("chenxing:oauth:refresh:{}", refresh.value),
            format!("chenxing:oauth:refresh:{}", rotatable.value),
            format!("chenxing:oauth:refresh:{}", rotated.value),
        ])
        .await
        .expect("cleanup Redis keys");
}

#[tokio::test]
#[serial(session_outbox)]
async fn session_revocation_generation_rejects_restored_old_payloads() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("generation-{}", Uuid::new_v4().simple()),
            email: format!("generation-{}@example.com", Uuid::new_v4().simple()),
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
            serde_json::to_string(&session).expect("session JSON"),
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
#[serial(session_outbox)]
async fn session_find_rejects_metadata_revocation_even_when_redis_payload_exists() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-revoke-{}", Uuid::new_v4().simple()),
            email: format!("metadata-revoke-{}@example.com", Uuid::new_v4().simple()),
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
#[serial(session_outbox)]
async fn session_find_uses_database_identity_for_cached_payloads() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-identity-{}", Uuid::new_v4().simple()),
            email: format!("metadata-identity-{}@example.com", Uuid::new_v4().simple()),
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
            email: format!("metadata-other-{}@example.com", Uuid::new_v4().simple()),
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

#[tokio::test]
#[serial(session_outbox)]
async fn session_save_keeps_metadata_pending_when_redis_connection_fails() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-connection-failure-{}", Uuid::new_v4().simple()),
            email: format!(
                "metadata-connection-failure-{}@example.com",
                Uuid::new_v4().simple()
            ),
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

fn session_store_key() -> [u8; 32] {
    [0x42; 32]
}

fn unavailable_redis_client() -> redis::Client {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve Redis port");
    let port = listener
        .local_addr()
        .expect("reserved Redis address")
        .port();
    drop(listener);
    redis::Client::open(format!("redis://127.0.0.1:{port}/")).expect("Redis URL")
}

#[tokio::test]
#[serial(session_outbox)]
async fn session_save_commits_metadata_and_replays_redis_after_connection_failure() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-save-{}", Uuid::new_v4().simple()),
            email: format!("outbox-save-{}@example.com", Uuid::new_v4().simple()),
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

#[tokio::test]
#[serial(session_outbox)]
async fn session_sync_projection_does_not_resurrect_a_concurrently_revoked_row() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-race-{}", Uuid::new_v4().simple()),
            email: format!("outbox-race-{}@example.com", Uuid::new_v4().simple()),
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

#[tokio::test]
#[serial(session_outbox)]
async fn session_revoke_keeps_database_authoritative_until_redis_recovers() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-revoke-{}", Uuid::new_v4().simple()),
            email: format!("outbox-revoke-{}@example.com", Uuid::new_v4().simple()),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox revoke user");
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
}

#[tokio::test]
#[serial(session_outbox)]
async fn session_revoke_for_user_commits_revocation_before_redis_delivery() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-single-{}", Uuid::new_v4().simple()),
            email: format!("outbox-single-{}@example.com", Uuid::new_v4().simple()),
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
#[serial(session_outbox)]
async fn session_revoke_all_commits_all_rows_before_redis_delivery() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-all-{}", Uuid::new_v4().simple()),
            email: format!("outbox-all-{}@example.com", Uuid::new_v4().simple()),
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
#[serial(session_outbox)]
async fn session_revoke_all_outbox_cleans_redis_after_user_deletion() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-delete-{}", Uuid::new_v4().simple()),
            email: format!("outbox-delete-{}@example.com", Uuid::new_v4().simple()),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox deletion user");
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
    unavailable
        .revoke_all_for_user(user.id)
        .await
        .expect("database batch revoke");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("delete user with pending revoke outbox");

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
        connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("stale Redis session")
    );

    available
        .process_pending_outbox()
        .await
        .expect("replay deletion revoke outbox");
    assert!(
        !connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("deleted Redis session")
    );
}
