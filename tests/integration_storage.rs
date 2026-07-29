use std::{env, time::Duration};

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
        ),
        client_repository::insert_owned_client(
            &pool,
            owner.id,
            registration(),
            format!("owned-client-b-{}", Uuid::new_v4().simple()),
            "hash".to_owned(),
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
    let session =
        Session::new("storage-user".to_owned(), Duration::from_secs(60)).expect("session");
    sessions
        .save(&session, Duration::from_secs(60))
        .await
        .expect("save session");
    assert_eq!(
        sessions
            .find(session.id)
            .await
            .expect("find session")
            .unwrap()
            .id,
        session.id
    );
    sessions.revoke(session.id).await.expect("revoke session");
    assert!(
        sessions
            .find(session.id)
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

    let _: usize = connection
        .del(&[
            format!("chenxing:session:{}", session.id),
            format!("chenxing:oauth:code:{}", code.value),
            format!("chenxing:oauth:refresh:{}", refresh.value),
        ])
        .await
        .expect("cleanup Redis keys");
}

#[tokio::test]
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
    let sessions = SessionStore::with_metadata(client.clone(), pool.clone());
    let session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    sessions
        .save(&session, Duration::from_secs(60))
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
            format!("chenxing:session:{}", session.id),
            serde_json::to_string(&session).expect("session JSON"),
            60,
        )
        .await
        .expect("restore old payload");
    assert!(
        sessions
            .find(session.id)
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
