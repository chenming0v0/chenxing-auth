use chenxing_auth::auth_factors::repository;
use chenxing_auth::db;
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn database() -> chenxing_auth::sqlx::PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("PostgreSQL is required for factor repository tests");
    db::migrate(&pool).await.expect("database migrations");
    pool
}

#[tokio::test]
async fn totp_factor_round_trip_returns_ciphertext_only() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, status, created_at)
         VALUES ($1, $2, $3, 'active', NOW())
         RETURNING id",
    )
    .bind(format!("factor-{suffix}"))
    .bind(format!("factor-{suffix}@example.com"))
    .bind("test-hash")
    .fetch_one(&pool)
    .await
    .expect("insert test user");

    let encrypted = vec![1_u8, 2, 3, 4];
    repository::insert_totp_factor(&pool, user_id, &encrypted)
        .await
        .expect("insert TOTP factor");
    assert_eq!(
        repository::find_totp_secret(&pool, user_id)
            .await
            .expect("find TOTP factor"),
        Some(encrypted)
    );
    assert_eq!(
        repository::list_factor_methods(&pool, user_id)
            .await
            .expect("list factor methods"),
        vec!["totp".to_owned()]
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup test user");
}
