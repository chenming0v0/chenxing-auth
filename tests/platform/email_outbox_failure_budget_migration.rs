use chenxing_auth::sqlx::{Connection, Executor, PgConnection};

use super::{failure_state, queued_email};

#[tokio::test]
async fn legacy_budget_migration_preserves_terminal_states_and_excludes_interrupted_claims() {
    let (_state, database, key_directory, _sender) = queued_email("email_budget_migration").await;
    let schema: String = chenxing_auth::sqlx::query_scalar("SELECT current_schema()::TEXT")
        .fetch_one(&database)
        .await
        .expect("isolated schema");
    // DDL 使用迁移角色，保持运行时连接只拥有业务表读写权限的部署契约。
    let migration_url = std::env::var("MIGRATION_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .unwrap_or_else(|| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let mut migration = PgConnection::connect(&migration_url)
        .await
        .expect("migration role connection");
    let _: String = chenxing_auth::sqlx::query_scalar(
        "SELECT set_config('search_path', format('%I, public', $1::TEXT), false)",
    )
    .bind(schema)
    .fetch_one(&mut migration)
    .await
    .expect("scope the migration role to the isolated schema");
    for (last_error, dead_lettered, expected_failures) in [
        (None, false, 0),
        (Some("delivery_failure"), false, 1),
        (Some("database_failure"), false, 0),
        (Some("delivery_failure"), true, 10),
    ] {
        chenxing_auth::sqlx::query(
            "UPDATE email_outbox
             SET attempts = 12, claim_generation = 12, claim_token = 'legacy-claim',
                 last_error = $1,
                 dead_lettered_at = CASE WHEN $2 THEN NOW() ELSE NULL END",
        )
        .bind(last_error)
        .bind(dead_lettered)
        .execute(&database)
        .await
        .expect("legacy outbox fixture");
        let terminal_before: Option<time::OffsetDateTime> =
            chenxing_auth::sqlx::query_scalar("SELECT dead_lettered_at FROM email_outbox")
                .fetch_one(&database)
                .await
                .expect("legacy terminal timestamp");
        chenxing_auth::sqlx::query("ALTER TABLE email_outbox DROP COLUMN failed_attempts")
            .execute(&mut migration)
            .await
            .expect("restore the pre-migration budget schema");
        migration
            .execute(include_str!(
                "../../migrations/0061_email_outbox_failure_budget.sql"
            ))
            .await
            .expect("apply the actual failure budget migration");

        assert_eq!(
            failure_state(&database).await,
            (
                12,
                expected_failures,
                dead_lettered,
                last_error.unwrap_or_default().to_owned()
            )
        );
        let preserved: (Option<time::OffsetDateTime>, i64, String) = chenxing_auth::sqlx::query_as(
            "SELECT dead_lettered_at, claim_generation, claim_token FROM email_outbox",
        )
        .fetch_one(&database)
        .await
        .expect("preserved legacy claim and terminal state");
        assert_eq!(preserved, (terminal_before, 12, "legacy-claim".to_owned()));
    }
    let _ = std::fs::remove_dir_all(key_directory);
}
