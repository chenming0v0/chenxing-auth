//! Issue #733：运行角色的同名临时表不能参与 SECURITY DEFINER 审计归档。

use chenxing_auth::sqlx::{PgPool, Postgres, Transaction};

use crate::db_isolation;

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

async fn database() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("audit_archive_search_path", &url).await
}

async fn runtime_transaction(pool: &PgPool) -> (Transaction<'_, Postgres>, String, String) {
    let mut transaction = pool.begin().await.expect("audit transaction");
    let (schema, owner): (String, String) =
        chenxing_auth::sqlx::query_as("SELECT current_schema(), current_user::text")
            .fetch_one(&mut *transaction)
            .await
            .expect("audit schema and function owner");
    // 使用事务局部角色，不轮换集群全局的运行角色口令，避免干扰并行测试。
    chenxing_auth::sqlx::query("SET LOCAL ROLE chenxing_runtime")
        .execute(&mut *transaction)
        .await
        .expect("runtime role");
    let privileges: (bool, bool, bool, bool) = chenxing_auth::sqlx::query_as(
        "SELECT has_table_privilege(current_user, $1, 'DELETE'),
                has_table_privilege(current_user, $2, 'INSERT'),
                has_function_privilege(current_user, $3, 'EXECUTE'),
                has_database_privilege(current_user, current_database(), 'TEMP')",
    )
    .bind(format!("{}.audit_events", quote_identifier(&schema)))
    .bind(format!(
        "{}.audit_events_archive",
        quote_identifier(&schema)
    ))
    .bind(format!(
        "{}.archive_audit_events(integer, integer)",
        quote_identifier(&schema)
    ))
    .fetch_one(&mut *transaction)
    .await
    .expect("runtime audit privileges");
    assert_eq!(privileges, (false, false, true, true));
    (
        transaction,
        quote_identifier(&schema),
        quote_identifier(&owner),
    )
}

async fn insert_real_event(transaction: &mut Transaction<'_, Postgres>, schema: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar(&format!(
        "INSERT INTO {schema}.audit_events
             (actor_type, action, resource_type, metadata, created_at)
         VALUES ('user', 'real_login', 'session', '{{}}'::jsonb,
                 CURRENT_TIMESTAMP - INTERVAL '2 days')
         RETURNING id"
    ))
    .fetch_one(&mut **transaction)
    .await
    .expect("runtime inserts a real hot event")
}

async fn archive(transaction: &mut Transaction<'_, Postgres>, schema: &str) -> i32 {
    chenxing_auth::sqlx::query_scalar(&format!("SELECT {schema}.archive_audit_events(1, 1000)"))
        .fetch_one(&mut **transaction)
        .await
        .expect("runtime invokes the archive function")
}

async fn assert_real_event_archived(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &str,
    id: i64,
) {
    let hot: Option<String> = chenxing_auth::sqlx::query_scalar(&format!(
        "SELECT action FROM {schema}.audit_events WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await
    .expect("real hot event");
    assert!(hot.is_none());
    let archived: String = chenxing_auth::sqlx::query_scalar(&format!(
        "SELECT action FROM {schema}.audit_events_archive WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(&mut **transaction)
    .await
    .expect("real archived event");
    assert_eq!(archived, "real_login");
    let marker: String = chenxing_auth::sqlx::query_scalar(
        "SELECT current_setting('chenxing.audit_events_archive')",
    )
    .fetch_one(&mut **transaction)
    .await
    .expect("archive bypass marker");
    assert_eq!(marker, "off");
    // 先验证真实归档结果，再检查函数配置，避免只靠字符串断言替代攻击回归。
    let (security_definer, configuration): (bool, Vec<String>) = chenxing_auth::sqlx::query_as(
        "SELECT prosecdef, proconfig FROM pg_catalog.pg_proc WHERE oid = $1::regprocedure",
    )
    .bind(format!("{schema}.archive_audit_events(integer, integer)"))
    .fetch_one(&mut **transaction)
    .await
    .expect("archive function configuration");
    assert!(security_definer);
    assert!(
        configuration
            .iter()
            .any(|value| value.starts_with("search_path=pg_catalog, ")
                && value.ends_with(", pg_temp"))
    );
}

#[tokio::test]
async fn temporary_hot_table_cannot_inject_forged_archive_events() {
    let pool = database().await;
    let (mut transaction, schema, owner) = runtime_transaction(&pool).await;
    let id = insert_real_event(&mut transaction, &schema).await;
    chenxing_auth::sqlx::query(&format!(
        "CREATE TEMP TABLE audit_events
             (LIKE {schema}.audit_events INCLUDING DEFAULTS INCLUDING CONSTRAINTS)
         ON COMMIT DROP"
    ))
    .execute(&mut *transaction)
    .await
    .expect("runtime creates a shadow hot table");
    chenxing_auth::sqlx::query(
        "INSERT INTO pg_temp.audit_events
             (id, actor_type, action, resource_type, metadata, created_at)
         VALUES ($1, 'user', 'forged_login', 'session', '{}'::jsonb,
                 CURRENT_TIMESTAMP - INTERVAL '2 days')",
    )
    .bind(id)
    .execute(&mut *transaction)
    .await
    .expect("forged hot event");
    // 即使函数所有者能访问伪表，也必须只处理真实表；不能靠权限错误碰巧挡住攻击。
    chenxing_auth::sqlx::query(&format!(
        "GRANT SELECT, DELETE ON pg_temp.audit_events TO {owner}"
    ))
    .execute(&mut *transaction)
    .await
    .expect("grant the definer access to the shadow hot table");

    assert_eq!(archive(&mut transaction, &schema).await, 1);
    assert_real_event_archived(&mut transaction, &schema, id).await;
    let forged: String =
        chenxing_auth::sqlx::query_scalar("SELECT action FROM pg_temp.audit_events WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *transaction)
            .await
            .expect("the shadow hot event stays untouched");
    assert_eq!(forged, "forged_login");
    transaction
        .rollback()
        .await
        .expect("rollback audit fixture");
}

#[tokio::test]
async fn temporary_archive_cannot_steal_real_hot_events() {
    let pool = database().await;
    let (mut transaction, schema, owner) = runtime_transaction(&pool).await;
    let id = insert_real_event(&mut transaction, &schema).await;
    chenxing_auth::sqlx::query(&format!(
        "CREATE TEMP TABLE audit_events_archive
             (LIKE {schema}.audit_events_archive INCLUDING ALL)
         ON COMMIT DROP"
    ))
    .execute(&mut *transaction)
    .await
    .expect("runtime creates a shadow archive");
    chenxing_auth::sqlx::query(&format!(
        "GRANT SELECT, INSERT ON pg_temp.audit_events_archive TO {owner}"
    ))
    .execute(&mut *transaction)
    .await
    .expect("grant the definer access to the shadow archive");

    assert_eq!(archive(&mut transaction, &schema).await, 1);
    assert_real_event_archived(&mut transaction, &schema, id).await;
    let stolen: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM pg_temp.audit_events_archive")
            .fetch_one(&mut *transaction)
            .await
            .expect("shadow archive count");
    assert_eq!(stolen, 0);
    assert_eq!(archive(&mut transaction, &schema).await, 0);
    transaction
        .rollback()
        .await
        .expect("rollback audit fixture");
}
