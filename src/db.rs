use std::borrow::Cow;

use crate::sqlx::{PgPool, PgPoolOptions};

use crate::config::Config;

#[path = "db_audit_boundary.rs"]
mod audit_boundary;
#[path = "db_migrate.rs"]
mod migrate_plan;
#[path = "db_pool.rs"]
mod pool;
#[path = "db_roles.rs"]
mod roles;

pub use audit_boundary::{
    AuditBoundaryError, AuditPrivileges, AuditRoleSeparation, verify_audit_append_only_boundary,
};
pub use migrate_plan::{
    AUDIT_ROLE_SEPARATION_ENV, MANAGE_RUNTIME_PASSWORD_ENV, MIGRATION_DATABASE_URL_ENV,
    MigrationPlan, MigrationPlanError,
};
pub use pool::{PoolRole, PoolSettingsError};
pub use roles::{RuntimePasswordPolicy, configure_runtime_role};

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
    /// 口令探测连不上数据库（TCP/TLS/DNS 等连接层故障）。连接层故障证明不了口令
    /// 状态，不能据此覆盖写——那会静默撤销运维侧的口令轮换（Issue #411）。
    /// 错误消息刻意不携带底层错误文本：sqlx 的连接错误可能内嵌连接串。
    #[error(
        "runtime database role password probe could not reach the database; the role password was left unchanged"
    )]
    RuntimePasswordProbeUnreachable(#[source] crate::sqlx::Error),
    /// 口令探测超时。同样属于"无法确认口令状态"，不覆盖写（Issue #411）。
    #[error("runtime database role password probe timed out; the role password was left unchanged")]
    RuntimePasswordProbeTimedOut(#[source] tokio::time::error::Elapsed),
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
    roles::ensure_runtime_role(database).await?;
    embedded_migrator().run(database).await?;
    verify_canonical_emails(database).await
}

/// 校验 `users.canonical_email` 与应用层的规范化结果一致（Issue #302）。
///
/// PostgreSQL 可以强制该列非空且唯一，却不能在不复制 UTS-46 实现的前提下证明它与
/// 展示邮箱一致。因此显式 migrate 命令会用唯一的权威实现 `EmailAddress` 复核
/// `xn--` 域名行。纯 ASCII 且结构合法的行由基线的应用写入契约保证，无需每次启动
/// 都扫描整张用户表。
///
/// 不一致时**拒绝启动**。这类行的匹配值一旦落错，登录会静默失败，而错误看起来
/// 像"密码不对"——放行是把一个可诊断的启动故障换成一个查不出原因的线上故障。
async fn verify_canonical_emails(
    database: &Database,
) -> Result<(), crate::sqlx::migrate::MigrateError> {
    let rows: Vec<(i64, String, String)> = crate::sqlx::query_as(
        "SELECT id, email, canonical_email FROM users
         WHERE EXISTS (
             SELECT 1
             FROM unnest(string_to_array(split_part(canonical_email, '@', 2), '.'))
                  AS domain_label(label)
             WHERE label LIKE 'xn--%'
         )
         ORDER BY id",
    )
    .fetch_all(database)
    .await?;

    let mut offending = Vec::new();
    for (id, email, canonical_email) in rows {
        let recomputed = crate::users::email::EmailAddress::parse(&email)
            .ok()
            .map(|parsed| parsed.into_canonical());
        if recomputed.as_deref() != Some(canonical_email.as_str()) {
            offending.push(id);
        }
    }

    if offending.is_empty() {
        return Ok(());
    }

    // 只报 id，不报地址本身：这条消息会进启动日志，而地址是个人数据。
    tracing::error!(
        user_ids = ?offending,
        "users.canonical_email disagrees with the application canonicalizer; refusing to start"
    );
    Err(crate::sqlx::migrate::MigrateError::Execute(
        crate::sqlx::Error::Protocol(format!(
            "canonical_email mismatch for {} user row(s): id in {:?}. \
             These rows carry an internationalized domain whose stored matching value \
             differs from what the application computes, so their owners cannot log in. \
             Fix users.email and canonical_email for each id, then restart. \
             The canonical value must come from the application EmailAddress parser.",
            offending.len(),
            offending,
        )),
    ))
}

fn embedded_migrator() -> crate::sqlx::migrate::Migrator {
    use crate::sqlx::migrate::{Migration, MigrationType, Migrator};

    let migrations = vec![Migration::new(
        1,
        Cow::Borrowed("current schema baseline"),
        MigrationType::Simple,
        normalize_migration_sql(include_str!("../migrations/0001_initial.sql")),
        false,
    )];

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
