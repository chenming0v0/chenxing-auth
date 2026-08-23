use crate::db_isolation;

use chenxing_auth::auth_factors::{
    domain::FactorMethod,
    store::{LoginTicketStore, LoginTicketStoreError},
};
use redis::{AsyncCommands, Client};
use uuid::Uuid;

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("login_ticket_epoch", &database_url).await
}

fn redis_client() -> Client {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    Client::open(redis_url).expect("Redis URL")
}

async fn insert_user(pool: &chenxing_auth::sqlx::PgPool) -> i64 {
    let suffix = Uuid::new_v4().simple().to_string();
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, canonical_email, password_hash, status, created_at, updated_at)
         VALUES ($1, $2, lower($2), 'test-hash', 'active', NOW(), NOW()) RETURNING id",
    )
    .bind(format!("ticket-{suffix}"))
    .bind(format!("ticket-{suffix}@example.com"))
    .fetch_one(pool)
    .await
    .expect("insert test user")
}

async fn issue_ticket(
    store: &LoginTicketStore,
    user_id: i64,
    session_epoch: i64,
) -> (String, String) {
    let holder_hash = "holder-hash".to_owned();
    let (ticket_id, ticket) = store
        .create_with_epoch_and_holder(
            user_id,
            vec![FactorMethod::Totp],
            session_epoch,
            holder_hash.clone(),
        )
        .await
        .expect("create ticket");
    assert_eq!(ticket.session_epoch, session_epoch);
    (ticket_id, holder_hash)
}

async fn redis_has_ticket(store: &LoginTicketStore, redis: &Client, ticket_id: &str) -> bool {
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let payload: Option<String> = connection
        .get(store.key_for_ticket(ticket_id))
        .await
        .expect("read ticket key");
    payload.is_some()
}

async fn cleanup_ticket(store: &LoginTicketStore, redis: &Client, ticket_id: &str) {
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: usize = connection
        .del(store.key_for_ticket(ticket_id))
        .await
        .expect("cleanup ticket");
}

#[tokio::test]
async fn password_epoch_change_invalidates_existing_login_ticket() {
    let pool = database().await;
    let redis = redis_client();
    let user_id = insert_user(&pool).await;
    let store = LoginTicketStore::new_with_pool(redis.clone(), pool.clone());
    let (ticket_id, holder_hash) = issue_ticket(&store, user_id, 0).await;
    assert!(
        store
            .find_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("find ticket")
            .is_some()
    );

    chenxing_auth::sqlx::query("UPDATE users SET session_epoch = 1 WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("advance session epoch");
    assert!(
        store
            .find_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("find stale ticket")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup user");
    cleanup_ticket(&store, &redis, &ticket_id).await;
}

/// Redis take deletes first, then the epoch lookup runs. A transient metadata
/// failure must put the ticket back; otherwise a retry finds nothing even
/// though no factor or session write happened.
#[tokio::test]
async fn take_restores_ticket_when_epoch_lookup_fails() {
    let pool = database().await;
    let redis = redis_client();
    let user_id = insert_user(&pool).await;
    let store = LoginTicketStore::new_with_pool(redis.clone(), pool.clone());
    let (ticket_id, holder_hash) = issue_ticket(&store, user_id, 0).await;

    chenxing_auth::sqlx::query("ALTER TABLE users RENAME TO users_epoch_lookup_unavailable")
        .execute(&pool)
        .await
        .expect("hide users table inside the isolated schema");

    let error = store
        .take_for_holder(&ticket_id, &holder_hash)
        .await
        .expect_err("epoch lookup failure must not look like a missing ticket");
    assert!(
        matches!(error, LoginTicketStoreError::Database(_)),
        "lookup failure must stay a database error, got {error:?}"
    );
    assert!(
        redis_has_ticket(&store, &redis, &ticket_id).await,
        "the taken ticket must be restored while metadata is still unavailable"
    );

    chenxing_auth::sqlx::query("ALTER TABLE users_epoch_lookup_unavailable RENAME TO users")
        .execute(&pool)
        .await
        .expect("restore users table for retry");
    assert!(
        store
            .find_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("find restored ticket")
            .is_some(),
        "retry must see the ticket after the database recovers"
    );
    assert!(
        store
            .take_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("retry take after lookup recovery")
            .is_some(),
        "the restored ticket must be consumable once metadata is back"
    );
    assert!(
        store
            .take_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("second take after successful retry")
            .is_none(),
        "a successful take must still consume the ticket"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup user");
}

/// Epoch mismatch is a security rejection, not an infrastructure failure.
/// Restoring that ticket would re-enable a revoked epoch.
#[tokio::test]
async fn take_consumes_ticket_when_epoch_mismatches() {
    let pool = database().await;
    let redis = redis_client();
    let user_id = insert_user(&pool).await;
    let store = LoginTicketStore::new_with_pool(redis.clone(), pool.clone());
    let (ticket_id, holder_hash) = issue_ticket(&store, user_id, 0).await;

    chenxing_auth::sqlx::query("UPDATE users SET session_epoch = 1 WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("advance session epoch");
    assert!(
        store
            .take_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("take stale ticket")
            .is_none(),
        "a known-stale epoch must reject the ticket"
    );
    assert!(
        !redis_has_ticket(&store, &redis, &ticket_id).await,
        "epoch mismatch must leave the ticket consumed"
    );

    chenxing_auth::sqlx::query("UPDATE users SET session_epoch = 0 WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("restore original epoch");
    assert!(
        store
            .find_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("find after epoch rollback")
            .is_none(),
        "rolling the epoch back must not resurrect a consumed stale ticket"
    );
    assert!(
        store
            .take_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("take after epoch rollback")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup user");
}

#[tokio::test]
async fn take_consumes_matching_ticket_once() {
    let pool = database().await;
    let redis = redis_client();
    let user_id = insert_user(&pool).await;
    let store = LoginTicketStore::new_with_pool(redis.clone(), pool.clone());
    let (ticket_id, holder_hash) = issue_ticket(&store, user_id, 0).await;

    assert!(
        store
            .take_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("take matching ticket")
            .is_some()
    );
    assert!(
        !redis_has_ticket(&store, &redis, &ticket_id).await,
        "a successful take must consume the ticket"
    );
    assert!(
        store
            .take_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("second take")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup user");
}
