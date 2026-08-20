use std::borrow::Cow;

use crate::sqlx::{PgPool, PgPoolOptions};

use crate::config::Config;

pub(crate) mod advisory_lock;
mod audit_boundary;
mod canonical_email;
mod migrate;
mod migration_compat;
mod migration_preflight;
mod migration_state;
mod pool;
mod roles;

pub use audit_boundary::{
    AuditBoundaryError, AuditPrivileges, AuditRoleSeparation, verify_audit_append_only_boundary,
};
pub use migrate::{
    AUDIT_ROLE_SEPARATION_ENV, MANAGE_RUNTIME_PASSWORD_ENV, MIGRATION_DATABASE_URL_ENV,
    MigrationPlan, MigrationPlanError, RuntimeAuditPosture,
};
pub use migration_state::{SchemaStateError, verify_schema_current};
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
    /// 口令探测未能证明口令不可用：连接层故障（TCP/TLS/DNS）或非口令授权失败
    /// （SQLSTATE 28000 及其他 28 类，Issue #455）。这些情况都不能覆盖写——
    /// 那会静默撤销运维侧的口令轮换（Issue #411）。
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
    migration_compat::run(database, embedded_migrator()).await?;
    canonical_email::verify(database).await
}

fn embedded_migrator() -> crate::sqlx::migrate::Migrator {
    use crate::sqlx::migrate::{Migration, MigrationType, Migrator};

    // Versions 1-27 have shipped and their SQL bytes are immutable. Keeping every
    // historical step here lets SQLx validate an existing database and continue
    // forward instead of treating the latest schema as a replacement version 1.
    let migrations: Vec<_> = [
        (
            1,
            "initial schema",
            include_str!("../../migrations/0001_initial.sql"),
        ),
        (2, "plans", include_str!("../../migrations/0002_plans.sql")),
        (
            3,
            "session outbox",
            include_str!("../../migrations/0003_session_outbox.sql"),
        ),
        (
            4,
            "relax deleted session outbox target",
            include_str!("../../migrations/0004_relax_deleted_session_outbox_target.sql"),
        ),
        (
            5,
            "session outbox event user",
            include_str!("../../migrations/0005_session_outbox_event_user.sql"),
        ),
        (
            6,
            "session epochs",
            include_str!("../../migrations/0006_session_epochs.sql"),
        ),
        (
            7,
            "plan default invariant",
            include_str!("../../migrations/0007_plan_default_invariant.sql"),
        ),
        (
            8,
            "admin query indexes",
            include_str!("../../migrations/0008_admin_query_indexes.sql"),
        ),
        (
            9,
            "system settings",
            include_str!("../../migrations/0009_system_settings.sql"),
        ),
        (
            10,
            "consent revoked at",
            include_str!("../../migrations/0010_consent_revoked_at.sql"),
        ),
        (
            11,
            "oauth provider pkce",
            include_str!("../../migrations/0011_oauth_provider_pkce.sql"),
        ),
        (
            12,
            "restore basic plan",
            include_str!("../../migrations/0012_restore_basic_plan.sql"),
        ),
        (
            13,
            "audit append only retention",
            include_str!("../../migrations/0013_audit_append_only_retention.sql"),
        ),
        (
            14,
            "session idle policy",
            include_str!("../../migrations/0014_session_idle_policy.sql"),
        ),
        (
            15,
            "admin search indexes",
            include_str!("../../migrations/0015_admin_search_indexes.sql"),
        ),
        (
            16,
            "client secret rotation version",
            include_str!("../../migrations/0016_client_secret_rotation_version.sql"),
        ),
        (
            17,
            "relax plan default policy",
            include_str!("../../migrations/0017_relax_plan_default_policy.sql"),
        ),
        (
            18,
            "seed security limits",
            include_str!("../../migrations/0018_seed_security_limits.sql"),
        ),
        (
            19,
            "audit runtime role",
            include_str!("../../migrations/0019_audit_runtime_role.sql"),
        ),
        (
            20,
            "user avatar",
            include_str!("../../migrations/0020_user_avatar.sql"),
        ),
        (
            21,
            "oauth provider require email verified claim",
            include_str!("../../migrations/0021_oauth_provider_require_email_verified_claim.sql"),
        ),
        (
            22,
            "session outbox retention",
            include_str!("../../migrations/0022_session_outbox_retention.sql"),
        ),
        (
            23,
            "consent state version",
            include_str!("../../migrations/0023_consent_state_version.sql"),
        ),
        (
            24,
            "runtime users sequence update",
            include_str!("../../migrations/0024_runtime_users_sequence_update.sql"),
        ),
        (
            25,
            "user canonical email",
            include_str!("../../migrations/0025_user_canonical_email.sql"),
        ),
        (
            26,
            "client secret refresh generation",
            include_str!("../../migrations/0026_client_secret_refresh_generation.sql"),
        ),
        (
            27,
            "repair canonical email constraint scope",
            include_str!("../../migrations/0027_repair_canonical_email_constraint_scope.sql"),
        ),
        (
            28,
            "controlled runtime issuer",
            include_str!("../../migrations/0028_issuer_runtime.sql"),
        ),
        (
            29,
            "bounded plan quotas",
            include_str!("../../migrations/0029_plan_quota_bounds.sql"),
        ),
        (
            30,
            "passkey state version",
            include_str!("../../migrations/0030_passkey_state_version.sql"),
        ),
        (
            31,
            "client operation idempotency",
            include_str!("../../migrations/0031_client_operation_idempotency.sql"),
        ),
        (
            32,
            "runtime migration ledger boundary",
            include_str!("../../migrations/0032_runtime_migration_ledger_boundary.sql"),
        ),
        (
            33,
            "registration invitation codes",
            include_str!("../../migrations/0033_registration_invitation_codes.sql"),
        ),
        (
            34,
            "user email change challenges",
            include_str!("../../migrations/0034_user_email_change_challenges.sql"),
        ),
        (
            35,
            "session outbox claim fence",
            include_str!("../../migrations/0035_session_outbox_claim_fence.sql"),
        ),
        (
            36,
            "revoke runtime archive insert",
            include_str!("../../migrations/0036_revoke_runtime_archive_insert.sql"),
        ),
        (
            37,
            "revoked access tokens",
            include_str!("../../migrations/0037_revoked_access_tokens.sql"),
        ),
    ]
    .into_iter()
    .map(|(version, description, sql)| {
        Migration::new(
            version,
            Cow::Borrowed(description),
            MigrationType::Simple,
            normalize_migration_sql(sql),
            false,
        )
    })
    .collect();

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
