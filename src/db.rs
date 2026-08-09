use std::borrow::Cow;

use crate::sqlx::{PgPool, PgPoolOptions};

use crate::config::Config;

#[path = "db_pool.rs"]
mod pool;

pub use pool::{PoolRole, PoolSettingsError};

pub type Database = PgPool;

pub const RUNTIME_DATABASE_ROLE: &str = "chenxing_runtime";

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("invalid runtime database URL")]
    InvalidRuntimeDatabaseUrl,
    #[error("runtime database password is missing; configure a separate runtime role")]
    MissingRuntimeDatabasePassword,
    #[error("database pool configuration is invalid: {0}")]
    PoolSettings(#[from] PoolSettingsError),
    #[error("database error")]
    Database(#[from] crate::sqlx::Error),
}

fn normalize_migration_sql(sql: &'static str) -> Cow<'static, str> {
    if sql.contains('\r') {
        Cow::Owned(sql.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(sql)
    }
}

/// 构建请求路径使用的应用查询池。
///
/// 该池的每条连接都带 `statement_timeout`（Issue #267），除非运维显式设置
/// `DB_STATEMENT_TIMEOUT_MS=0`。
pub fn connect(config: &Config) -> Result<Database, DbError> {
    connect_for(PoolRole::Application, &config.database_url)
}

/// 构建迁移与显式维护命令使用的池，不施加 `statement_timeout`。
///
/// 迁移和审计归档的正常耗时可以远超请求路径的上限，共用应用池会让它们被中途掐断。
pub fn connect_maintenance(database_url: &str) -> Result<Database, DbError> {
    connect_for(PoolRole::Maintenance, database_url)
}

/// 按用途构建连接池。
///
/// 两种用途只在 `statement_timeout` 上分叉，容量与回收策略保持一致：维护池独占的
/// 容量参数会引入新的失败模式（例如单连接池在任何嵌套获取处死锁），而它并不解决
/// 本 Issue 的问题。sqlx 的 `max_lifetime` 只在连接归还或获取时判定，不会打断已经
/// 借出的长任务，所以迁移即使跑满 30 分钟也不会被回收策略截断。
///
/// `statement_timeout` 通过 `after_connect` 设置在每条新连接的会话上，而不是塞进
/// URL 的 `options` 参数：URL 可能已经带了运维自己的 `options`，覆盖它会静默丢掉
/// 那些设置；`after_connect` 也在 PgBouncer 之类的连接代理后面行为更可预测。
/// 每条连接只多一次往返，而 `idle_timeout` / `max_lifetime` 让连接被复用很多次，
/// 这次往返摊薄到可忽略。
///
/// 上限对请求路径上的阻塞式等待同样生效：`pg_advisory_xact_lock` 和 `FOR UPDATE`
/// 在锁竞争下会被取消并返回错误，而不是无限期占住连接。调用方本来就要处理数据库
/// 错误，这正是需要的行为。Session outbox worker 走应用池，被取消时按既有重试循环
/// 重新领取任务。
pub fn connect_for(role: PoolRole, database_url: &str) -> Result<Database, DbError> {
    let settings = pool::pool_settings_from_env()?;
    let mut options = PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .acquire_timeout(settings.acquire_timeout)
        .idle_timeout(settings.idle_timeout)
        .max_lifetime(settings.max_lifetime);

    let statement_timeout = match role {
        PoolRole::Application => settings.statement_timeout,
        PoolRole::Maintenance => None,
    };

    if let Some(timeout) = statement_timeout {
        // 毫秒数由 pool 模块校验过取值范围，这里作为绑定参数传给 set_config，
        // 不做字符串拼接。第三个参数 false = 会话级，作用于整条连接的生命周期。
        let milliseconds = timeout.as_millis().to_string();
        options = options.after_connect(move |connection, _meta| {
            let milliseconds = milliseconds.clone();
            Box::pin(async move {
                crate::sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                    .bind(milliseconds)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        });
    }

    options.connect_lazy(database_url).map_err(DbError::from)
}

pub async fn check_ready(database: &Database) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query("SELECT 1")
        .execute(database)
        .await
        .map(|_| ())
}

pub async fn migrate(database: &Database) -> Result<(), crate::sqlx::migrate::MigrateError> {
    embedded_migrator().run(database).await
}

/// Ensure the fixed runtime role exists with the password carried by the
/// runtime `DATABASE_URL`. The migration role owns the audit tables; the
/// runtime role only receives the explicitly granted privileges.
pub async fn configure_runtime_role(
    database: &Database,
    runtime_database_url: &str,
) -> Result<(), DbError> {
    let url =
        url::Url::parse(runtime_database_url).map_err(|_| DbError::InvalidRuntimeDatabaseUrl)?;
    let password = url
        .password()
        .filter(|password| !password.is_empty())
        .ok_or(DbError::MissingRuntimeDatabasePassword)?;

    let role_exists: bool =
        crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(RUNTIME_DATABASE_ROLE)
            .fetch_one(database)
            .await?;
    if !role_exists {
        crate::sqlx::query(&format!(
            "CREATE ROLE {} LOGIN",
            quote_ident(RUNTIME_DATABASE_ROLE)
        ))
        .execute(database)
        .await?;
    }

    crate::sqlx::query(&format!(
        "ALTER ROLE {} WITH LOGIN PASSWORD {}",
        quote_ident(RUNTIME_DATABASE_ROLE),
        quote_literal(password)
    ))
    .execute(database)
    .await?;
    Ok(())
}

fn quote_ident(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn embedded_migrator() -> crate::sqlx::migrate::Migrator {
    use crate::sqlx::migrate::{Migration, MigrationType, Migrator};

    let migrations = vec![
        Migration::new(
            1,
            Cow::Borrowed("unified identity baseline"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0001_initial.sql")),
            false,
        ),
        Migration::new(
            2,
            Cow::Borrowed("plans and entitlements"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0002_plans.sql")),
            false,
        ),
        Migration::new(
            3,
            Cow::Borrowed("session outbox consistency"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0003_session_outbox.sql")),
            false,
        ),
        Migration::new(
            4,
            Cow::Borrowed("session outbox deleted target cleanup"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!(
                "../migrations/0004_relax_deleted_session_outbox_target.sql"
            )),
            false,
        ),
        Migration::new(
            5,
            Cow::Borrowed("session outbox event user retention"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!(
                "../migrations/0005_session_outbox_event_user.sql"
            )),
            false,
        ),
        Migration::new(
            6,
            Cow::Borrowed("session revocation epochs"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0006_session_epochs.sql")),
            false,
        ),
        Migration::new(
            7,
            Cow::Borrowed("plan default invariant"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!(
                "../migrations/0007_plan_default_invariant.sql"
            )),
            false,
        ),
        Migration::new(
            8,
            Cow::Borrowed("admin query indexes"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0008_admin_query_indexes.sql")),
            false,
        ),
        Migration::new(
            9,
            Cow::Borrowed("system settings seeds"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0009_system_settings.sql")),
            false,
        ),
        Migration::new(
            10,
            Cow::Borrowed("durable consent revocation"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0010_consent_revoked_at.sql")),
            false,
        ),
        Migration::new(
            11,
            Cow::Borrowed("external provider PKCE toggle"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0011_oauth_provider_pkce.sql")),
            false,
        ),
        Migration::new(
            12,
            Cow::Borrowed("restore basic plan seed"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0012_restore_basic_plan.sql")),
            false,
        ),
        Migration::new(
            13,
            Cow::Borrowed("audit append-only retention"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!(
                "../migrations/0013_audit_append_only_retention.sql"
            )),
            false,
        ),
        Migration::new(
            14,
            Cow::Borrowed("session idle policy"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0014_session_idle_policy.sql")),
            false,
        ),
        Migration::new(
            15,
            Cow::Borrowed("admin search indexes"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0015_admin_search_indexes.sql")),
            false,
        ),
        Migration::new(
            16,
            Cow::Borrowed("client secret rotation compare-and-swap version"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!(
                "../migrations/0016_client_secret_rotation_version.sql"
            )),
            false,
        ),
        Migration::new(
            17,
            Cow::Borrowed("relax plan default policy"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!(
                "../migrations/0017_relax_plan_default_policy.sql"
            )),
            false,
        ),
        Migration::new(
            18,
            Cow::Borrowed("seed security limits"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0018_seed_security_limits.sql")),
            false,
        ),
        Migration::new(
            19,
            Cow::Borrowed("audit runtime role separation"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0019_audit_runtime_role.sql")),
            true,
        ),
        Migration::new(
            20,
            Cow::Borrowed("user avatar storage"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0020_user_avatar.sql")),
            false,
        ),
        Migration::new(
            21,
            Cow::Borrowed("external provider requires email_verified claim"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!(
                "../migrations/0021_oauth_provider_require_email_verified_claim.sql"
            )),
            false,
        ),
        Migration::new(
            22,
            Cow::Borrowed("session outbox retention and dead letters"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!(
                "../migrations/0022_session_outbox_retention.sql"
            )),
            false,
        ),
        Migration::new(
            23,
            Cow::Borrowed("consent state version for cache staleness detection"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0023_consent_state_version.sql")),
            false,
        ),
    ];

    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_migration_sql;

    #[test]
    fn migration_sql_normalizes_windows_line_endings() {
        assert_eq!(
            normalize_migration_sql("CREATE TABLE test;\r\n"),
            "CREATE TABLE test;\n"
        );
    }
}
