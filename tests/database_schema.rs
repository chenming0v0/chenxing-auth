use std::env;

use chenxing_auth::{db, sqlx::postgres::PgPoolOptions};

async fn database() -> chenxing_auth::sqlx::PgPool {
    let url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("PostgreSQL is required for schema tests");
    db::migrate(&pool).await.expect("database migrations");
    pool
}

async fn assert_column(
    pool: &chenxing_auth::sqlx::PgPool,
    table: &str,
    column: &str,
    data_type: &str,
    nullable: bool,
) {
    let row: Option<(String, String, String)> = chenxing_auth::sqlx::query_as(
        "SELECT data_type, is_nullable, udt_name
         FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_optional(pool)
    .await
    .expect("column metadata query");
    let (actual_type, is_nullable, udt_name) = row.expect("column exists");
    assert_eq!(
        actual_type, data_type,
        "unexpected data type for {table}.{column}"
    );
    if data_type == "bigint" {
        assert_eq!(udt_name, "int8");
    }
    assert_eq!(
        is_nullable == "YES",
        nullable,
        "unexpected nullability for {table}.{column}"
    );
}

async fn assert_identity(pool: &chenxing_auth::sqlx::PgPool, table: &str, column: &str) {
    let generated: Option<String> = chenxing_auth::sqlx::query_scalar(
        "SELECT is_identity
         FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_optional(pool)
    .await
    .expect("identity metadata query");
    assert_eq!(generated.as_deref(), Some("YES"));
}

async fn assert_check_contains(pool: &chenxing_auth::sqlx::PgPool, table: &str, name: &str) {
    let definition: String = chenxing_auth::sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid)
         FROM pg_constraint
         WHERE connamespace = current_schema()::regnamespace AND conrelid = $1::regclass AND conname = $2",
    )
    .bind(table)
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("check constraint query");
    for value in ["user", "admin", "owner"] {
        assert!(
            definition.contains(value),
            "{name} does not contain {value}: {definition}"
        );
    }
}

async fn assert_table_missing(pool: &chenxing_auth::sqlx::PgPool, table: &str) {
    let exists: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT to_regclass(current_schema() || '.' || $1) IS NOT NULL",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .expect("table metadata query");
    assert!(!exists, "legacy table still exists: {table}");
}

async fn assert_fk(
    pool: &chenxing_auth::sqlx::PgPool,
    table: &str,
    column: &str,
    referenced_table: &str,
    referenced_column: &str,
) {
    let matches: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM pg_constraint c
         JOIN pg_class source_table ON source_table.oid = c.conrelid
         JOIN pg_class target_table ON target_table.oid = c.confrelid
         JOIN pg_attribute source_column
           ON source_column.attrelid = c.conrelid AND source_column.attnum = ANY(c.conkey)
         JOIN pg_attribute target_column
           ON target_column.attrelid = c.confrelid AND target_column.attnum = ANY(c.confkey)
         WHERE c.contype = 'f'
           AND source_table.relname = $1
           AND source_column.attname = $2
           AND target_table.relname = $3
           AND target_column.attname = $4",
    )
    .bind(table)
    .bind(column)
    .bind(referenced_table)
    .bind(referenced_column)
    .fetch_one(pool)
    .await
    .expect("foreign key metadata query");
    assert_eq!(
        matches, 1,
        "missing foreign key {table}.{column} -> {referenced_table}.{referenced_column}"
    );
}

#[tokio::test]
async fn unified_identity_schema_uses_bigint_entities_and_no_admin_table() {
    let pool = database().await;

    assert_column(&pool, "users", "id", "bigint", false).await;
    assert_identity(&pool, "users", "id").await;
    assert_check_contains(&pool, "users", "users_role_check").await;
    assert_table_missing(&pool, "admins").await;
    assert_column(&pool, "user_passkeys", "user_id", "bigint", false).await;
    assert_fk(&pool, "user_passkeys", "user_id", "users", "id").await;
    assert_column(&pool, "oauth_clients", "id", "bigint", false).await;
    assert_identity(&pool, "oauth_clients", "id").await;
    assert_column(&pool, "oauth_providers", "id", "bigint", false).await;
    assert_identity(&pool, "oauth_providers", "id").await;
    assert_column(&pool, "user_sessions", "session_payload", "bytea", true).await;
    assert_column(&pool, "session_outbox", "id", "bigint", false).await;
    assert_identity(&pool, "session_outbox", "id").await;
    assert_column(
        &pool,
        "session_outbox",
        "available_at",
        "timestamp with time zone",
        false,
    )
    .await;
    assert_column(&pool, "session_outbox", "attempts", "integer", false).await;
    assert_fk(&pool, "session_outbox", "session_id", "user_sessions", "id").await;

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let ids: Vec<i64> = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, created_at, updated_at)
         VALUES ($1, $2, 'test-hash', NOW(), NOW()),
                ($3, $4, 'test-hash', NOW(), NOW()),
                ($5, $6, 'test-hash', NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("schema-a-{suffix}"))
    .bind(format!("schema-a-{suffix}@example.com"))
    .bind(format!("schema-b-{suffix}"))
    .bind(format!("schema-b-{suffix}@example.com"))
    .bind(format!("schema-c-{suffix}"))
    .bind(format!("schema-c-{suffix}@example.com"))
    .fetch_all(&pool)
    .await
    .expect("insert sequential users");
    assert_eq!(ids.len(), 3);
    assert_eq!(ids[1], ids[0] + 1);
    assert_eq!(ids[2], ids[1] + 1);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&pool)
        .await
        .expect("cleanup schema users");
}
