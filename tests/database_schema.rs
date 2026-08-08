#[path = "support/db_isolation.rs"]
mod db_isolation;

use chenxing_auth::sqlx::postgres::PgPoolOptions;
use std::env;

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("database_schema", &database_url).await
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

async fn assert_constraint_contains(
    pool: &chenxing_auth::sqlx::PgPool,
    table: &str,
    name: &str,
    values: &[&str],
) {
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
    for &value in values {
        assert!(
            definition.contains(value),
            "{name} does not contain {value}: {definition}"
        );
    }
}

async fn assert_check_contains(pool: &chenxing_auth::sqlx::PgPool, table: &str, name: &str) {
    assert_constraint_contains(pool, table, name, &["user", "admin", "owner"]).await;
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

async fn assert_index(pool: &chenxing_auth::sqlx::PgPool, index: &str) {
    let exists: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
             FROM pg_indexes
             WHERE schemaname = current_schema() AND indexname = $1
         )",
    )
    .bind(index)
    .fetch_one(pool)
    .await
    .expect("index metadata query");
    assert!(exists, "missing index: {index}");
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
           AND source_table.relnamespace = current_schema()::regnamespace
           AND target_table.relnamespace = current_schema()::regnamespace
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
    assert_constraint_contains(
        &pool,
        "plans",
        "plans_default_must_be_active",
        &["status", "is_default"],
    )
    .await;
    assert_column(&pool, "user_sessions", "session_payload", "bytea", true).await;
    assert_column(
        &pool,
        "user_sessions",
        "last_seen_at",
        "timestamp with time zone",
        false,
    )
    .await;
    assert_column(&pool, "users", "session_epoch", "bigint", false).await;
    assert_column(&pool, "user_sessions", "session_epoch", "bigint", false).await;
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
    assert_column(&pool, "session_outbox", "generation", "bigint", false).await;
    assert_fk(&pool, "session_outbox", "session_id", "user_sessions", "id").await;
    for index in [
        "users_admin_query_order_idx",
        "users_admin_query_status_idx",
        "users_admin_search_trgm_idx",
        "oauth_clients_admin_query_order_idx",
        "oauth_clients_admin_query_status_idx",
        "oauth_clients_admin_search_trgm_idx",
        "audit_events_action_idx",
        "audit_events_archive_action_idx",
        "user_sessions_active_created_idx",
    ] {
        assert_index(&pool, index).await;
    }

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

#[tokio::test]
async fn audit_events_are_immutable_and_old_rows_move_to_archive() {
    let pool = database().await;
    let event_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO audit_events
             (actor_type, action, resource_type, metadata, created_at)
         VALUES ('test', 'append_only_test', 'test', '{}'::jsonb,
                 CURRENT_TIMESTAMP - INTERVAL '2 days')
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("insert old audit event");

    let update =
        chenxing_auth::sqlx::query("UPDATE audit_events SET action = 'mutated' WHERE id = $1")
            .bind(event_id)
            .execute(&pool)
            .await;
    assert!(update.is_err(), "audit UPDATE must be rejected");

    let delete = chenxing_auth::sqlx::query("DELETE FROM audit_events WHERE id = $1")
        .bind(event_id)
        .execute(&pool)
        .await;
    assert!(delete.is_err(), "direct audit DELETE must be rejected");

    let archived: i32 = chenxing_auth::sqlx::query_scalar("SELECT archive_audit_events(1, 1000)")
        .fetch_one(&pool)
        .await
        .expect("archive old audit event");
    assert_eq!(archived, 1);

    let archived_action: String =
        chenxing_auth::sqlx::query_scalar("SELECT action FROM audit_events_archive WHERE id = $1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .expect("archived audit event");
    assert_eq!(archived_action, "append_only_test");
}

#[tokio::test]
async fn runtime_role_cannot_delete_audit_and_uses_security_definer_archive() {
    let pool = database().await;
    let schema: String = chenxing_auth::sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .expect("current schema");

    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let mut runtime_url = url::Url::parse(&database_url).expect("runtime database URL");
    runtime_url
        .set_username(chenxing_auth::db::RUNTIME_DATABASE_ROLE)
        .expect("set runtime username");
    let password = format!("runtime-{}", uuid::Uuid::new_v4().simple());
    runtime_url
        .set_password(Some(&password))
        .expect("set runtime password");

    chenxing_auth::db::configure_runtime_role(&pool, runtime_url.as_str())
        .await
        .expect("configure runtime role");

    let schema_for_pool = schema.clone();
    let runtime_pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _meta| {
            let schema = schema_for_pool.clone();
            Box::pin(async move {
                chenxing_auth::sqlx::query(&format!("SET search_path TO {schema}"))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(runtime_url.as_str())
        .await
        .expect("runtime role connection");

    let event_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO audit_events
             (actor_type, action, resource_type, metadata, created_at)
         VALUES ('test', 'runtime_role_test', 'test', '{}'::jsonb,
                 CURRENT_TIMESTAMP - INTERVAL '2 days')
         RETURNING id",
    )
    .fetch_one(&runtime_pool)
    .await
    .expect("runtime role can insert audit events");

    for privilege in ["DELETE", "UPDATE", "TRUNCATE"] {
        let granted: bool = chenxing_auth::sqlx::query_scalar(
            "SELECT has_table_privilege(current_user, 'audit_events', $1)",
        )
        .bind(privilege)
        .fetch_one(&runtime_pool)
        .await
        .expect("audit privilege check");
        assert!(
            !granted,
            "runtime role must not be granted {privilege} on audit_events"
        );
    }

    chenxing_auth::sqlx::query("SELECT set_config('chenxing.audit_events_archive', 'on', false)")
        .execute(&runtime_pool)
        .await
        .expect("runtime role can set the archive marker");
    let delete = chenxing_auth::sqlx::query("DELETE FROM audit_events WHERE id = $1")
        .bind(event_id)
        .execute(&runtime_pool)
        .await;
    assert!(
        delete.is_err(),
        "runtime DELETE with the archive marker must still be rejected"
    );

    let archived: i32 = chenxing_auth::sqlx::query_scalar("SELECT archive_audit_events(1, 1000)")
        .fetch_one(&runtime_pool)
        .await
        .expect("runtime role can archive through SECURITY DEFINER function");
    assert_eq!(archived, 1);
}
