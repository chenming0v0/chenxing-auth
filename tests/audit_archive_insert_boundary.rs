//! Issue #648：运行时角色不得 INSERT `audit_events_archive`。
//!
//! 0019 只收回了归档表的 UPDATE/DELETE/TRUNCATE，INSERT 仍留给 `chenxing_runtime`。
//! 被攻破的运行时因此可以：
//! 1. 直接写入伪造的 actor/action/metadata/时间戳，安全事件 API 会把它当成不可变历史；
//! 2. 抢先插入与热表相同的 id，`archive_audit_events` 的 `ON CONFLICT DO NOTHING`
//!    会跳过真实复制，热表行留着，归档里却是伪造行。
//!
//! 0036 收回 INSERT；启动期校验把归档 INSERT 当成 mutability，授权存在则 fail closed。

use chenxing_auth::sqlx::PgPool;
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use std::env;

#[path = "support/db_isolation.rs"]
mod db_isolation;

async fn owner_pool() -> PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("audit_archive_insert_boundary", &database_url).await
}

async fn connect_runtime(owner: &PgPool) -> PgPool {
    let schema: String = chenxing_auth::sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(owner)
        .await
        .expect("current schema");
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let mut runtime_url = url::Url::parse(&database_url).expect("runtime database URL");
    runtime_url
        .set_username(chenxing_auth::db::RUNTIME_DATABASE_ROLE)
        .expect("set runtime username");
    runtime_url
        .set_password(Some(&format!("runtime-{}", uuid::Uuid::new_v4().simple())))
        .expect("set runtime password");
    chenxing_auth::db::configure_runtime_role(
        owner,
        runtime_url.as_str(),
        chenxing_auth::db::RuntimePasswordPolicy::Managed,
    )
    .await
    .expect("configure runtime role");

    PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _meta| {
            let schema = schema.clone();
            Box::pin(async move {
                chenxing_auth::sqlx::query(&format!("SET search_path TO {schema}"))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(runtime_url.as_str())
        .await
        .expect("runtime role connection")
}

async fn insert_old_hot_event(pool: &PgPool, action: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO audit_events
             (actor_type, action, resource_type, metadata, created_at)
         VALUES ('user', $1, 'session', '{}'::jsonb,
                 CURRENT_TIMESTAMP - INTERVAL '2 days')
         RETURNING id",
    )
    .bind(action)
    .fetch_one(pool)
    .await
    .expect("insert hot audit event")
}

async fn insert_archive_row(
    pool: &PgPool,
    id: i64,
    action: &str,
) -> Result<u64, chenxing_auth::sqlx::Error> {
    chenxing_auth::sqlx::query(
        "INSERT INTO audit_events_archive
             (id, actor_type, actor_user_id, action, resource_type, resource_id,
              metadata, created_at)
         VALUES ($1, 'user', NULL, $2, 'session', NULL, '{}'::jsonb,
                 CURRENT_TIMESTAMP - INTERVAL '2 days')",
    )
    .bind(id)
    .bind(action)
    .execute(pool)
    .await
    .map(|result| result.rows_affected())
}

async fn archive_batch(pool: &PgPool) -> i32 {
    chenxing_auth::sqlx::query_scalar("SELECT archive_audit_events(1, 1000)")
        .fetch_one(pool)
        .await
        .expect("archive_audit_events")
}

async fn hot_action(pool: &PgPool, id: i64) -> Option<String> {
    chenxing_auth::sqlx::query_scalar("SELECT action FROM audit_events WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("read hot audit event")
}

async fn archive_action(pool: &PgPool, id: i64) -> Option<String> {
    chenxing_auth::sqlx::query_scalar("SELECT action FROM audit_events_archive WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("read archived audit event")
}

/// 回归：运行时 INSERT 归档被拒；授权一旦出现，校验 fail closed，且能跳过真实归档。
#[tokio::test]
async fn runtime_cannot_forge_or_preempt_archive_rows() {
    let owner = owner_pool().await;
    let runtime = connect_runtime(&owner).await;

    let privileges = chenxing_auth::db::verify_audit_append_only_boundary(
        &owner,
        chenxing_auth::db::RUNTIME_DATABASE_ROLE,
        chenxing_auth::db::AuditRoleSeparation::Require,
    )
    .await
    .expect("baseline after 0036 must satisfy the append-only boundary");
    assert!(privileges.can_insert, "hot-table INSERT remains required");
    assert!(privileges.can_select, "archive SELECT remains required");
    assert!(privileges.can_archive);
    assert!(!privileges.can_mutate);

    let can_insert_archive: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT has_table_privilege($1, 'audit_events_archive', 'INSERT')",
    )
    .bind(chenxing_auth::db::RUNTIME_DATABASE_ROLE)
    .fetch_one(&owner)
    .await
    .expect("archive INSERT privilege");
    assert!(
        !can_insert_archive,
        "0036 must revoke runtime INSERT on the archive"
    );

    let hot_id = insert_old_hot_event(&runtime, "real_login").await;
    let forged = insert_archive_row(&runtime, hot_id, "forged_login").await;
    assert!(
        forged.is_err(),
        "runtime INSERT into audit_events_archive must be rejected"
    );
    assert!(archive_action(&owner, hot_id).await.is_none());

    assert_eq!(archive_batch(&runtime).await, 1);
    assert_eq!(
        archive_action(&runtime, hot_id).await,
        Some("real_login".to_owned()),
        "runtime must still SELECT archive history after INSERT is revoked"
    );
    assert!(hot_action(&owner, hot_id).await.is_none());

    chenxing_auth::sqlx::query("GRANT INSERT ON TABLE audit_events_archive TO chenxing_runtime")
        .execute(&owner)
        .await
        .expect("reproduce the 0019 leftover INSERT grant");

    let error = chenxing_auth::db::verify_audit_append_only_boundary(
        &owner,
        chenxing_auth::db::RUNTIME_DATABASE_ROLE,
        chenxing_auth::db::AuditRoleSeparation::Require,
    )
    .await
    .expect_err("archive INSERT must fail closed");
    assert!(
        matches!(
            error,
            chenxing_auth::db::AuditBoundaryError::RuntimeRoleCanMutateAudit { .. }
        ),
        "verifier must treat archive INSERT as forbidden mutability, got {error}"
    );

    let colliding_id = insert_old_hot_event(&runtime, "real_consent").await;
    insert_archive_row(&runtime, colliding_id, "forged_consent")
        .await
        .expect("the leftover INSERT grant lets runtime preinsert a colliding archive id");
    assert_eq!(
        archive_batch(&runtime).await,
        0,
        "ON CONFLICT DO NOTHING must skip the real hot row once a colliding archive id exists"
    );
    assert_eq!(
        hot_action(&owner, colliding_id).await,
        Some("real_consent".to_owned()),
        "the real hot row must remain when archival is preempted"
    );
    assert_eq!(
        archive_action(&owner, colliding_id).await,
        Some("forged_consent".to_owned()),
        "security-event history would then show the forged archive row"
    );

    chenxing_auth::sqlx::query("REVOKE INSERT ON TABLE audit_events_archive FROM chenxing_runtime")
        .execute(&owner)
        .await
        .expect("restore the 0036 revoke");

    chenxing_auth::db::verify_audit_append_only_boundary(
        &owner,
        chenxing_auth::db::RUNTIME_DATABASE_ROLE,
        chenxing_auth::db::AuditRoleSeparation::Require,
    )
    .await
    .expect("revoking archive INSERT restores the boundary");

    let recovered_id = insert_old_hot_event(&runtime, "recovered_login").await;
    assert!(
        insert_archive_row(&runtime, recovered_id, "forged_again")
            .await
            .is_err(),
        "runtime INSERT must stay rejected after the grant is revoked"
    );
    assert_eq!(archive_batch(&runtime).await, 1);
    assert_eq!(
        archive_action(&owner, recovered_id).await,
        Some("recovered_login".to_owned())
    );
}
