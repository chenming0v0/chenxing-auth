#[path = "support/db_isolation.rs"]
mod db_isolation;

use chenxing_auth::auth_factors::{domain::FactorMethod, store::LoginTicketStore};
use redis::Client;
use serial_test::serial;
use uuid::Uuid;

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("login_ticket_epoch", &database_url).await
}

#[tokio::test]
#[serial(login_ticket_epoch)]
async fn password_epoch_change_invalidates_existing_login_ticket() {
    let pool = database().await;
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = Client::open(redis_url).expect("Redis URL");
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, status, created_at, updated_at)
         VALUES ($1, $2, 'test-hash', 'active', NOW(), NOW()) RETURNING id",
    )
    .bind(format!("ticket-{suffix}"))
    .bind(format!("ticket-{suffix}@example.com"))
    .fetch_one(&pool)
    .await
    .expect("insert test user");

    let store = LoginTicketStore::new_with_pool(redis.clone(), pool.clone());
    let holder_hash = "holder-hash".to_owned();
    let (ticket_id, ticket) = store
        .create_with_epoch_and_holder(user_id, vec![FactorMethod::Totp], 0, holder_hash.clone())
        .await
        .expect("create ticket");
    assert!(
        store
            .find_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("find ticket")
            .is_some()
    );
    assert_eq!(ticket.session_epoch, 0);

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
}
