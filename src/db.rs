use std::borrow::Cow;
use std::time::Duration;

use crate::sqlx::{PgPool, PgPoolOptions};

use crate::config::Config;

pub type Database = PgPool;

fn normalize_migration_sql(sql: &'static str) -> Cow<'static, str> {
    if sql.contains('\r') {
        Cow::Owned(sql.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(sql)
    }
}

/// 连接池参数，从环境变量读取。
/// 后续应收敛进 AppConfig，当前为避免并发改动冲突而就地读取。
struct PoolSettings {
    max_connections: u32,
    acquire_timeout: Duration,
    idle_timeout: Duration,
    max_lifetime: Duration,
}

/// 从环境变量解析连接池参数，解析失败时记录 warn 并回退默认值。
///
/// 默认值依据：
/// - `max_connections = 10`：向后兼容，不改变现有部署行为。
/// - `acquire_timeout = 5s`：认证服务要求快速失败；sqlx 默认 30s 会在连接耗尽时
///   导致请求长时间阻塞，触发级联故障。5s 足以覆盖正常连接建立 + 池等待。
/// - `idle_timeout = 600s`：定期回收空闲连接，避免数据库端关闭连接后复用失效。
/// - `max_lifetime = 1800s`（30 分钟）：让连接定期轮换，消除长连接累积的服务端
///   状态，并在数据库主从切换后自然重连。
fn pool_settings_from_env() -> PoolSettings {
    pool_settings_from_lookup(|key| std::env::var(key).ok())
}

/// 连接池参数解析核心逻辑，接受任意 lookup 函数，方便单元测试。
fn pool_settings_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> PoolSettings {
    const DEFAULT_MAX_CONNECTIONS: u32 = 10;
    const DEFAULT_ACQUIRE_TIMEOUT_SECS: u64 = 5;
    const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 600;
    const DEFAULT_MAX_LIFETIME_SECS: u64 = 1800;

    let max_connections = parse_pool_u32(
        lookup("DB_MAX_CONNECTIONS").as_deref(),
        "DB_MAX_CONNECTIONS",
        DEFAULT_MAX_CONNECTIONS,
    );
    let acquire_timeout_secs = parse_pool_u64(
        lookup("DB_ACQUIRE_TIMEOUT_SECONDS").as_deref(),
        "DB_ACQUIRE_TIMEOUT_SECONDS",
        DEFAULT_ACQUIRE_TIMEOUT_SECS,
    );
    let idle_timeout_secs = parse_pool_u64(
        lookup("DB_IDLE_TIMEOUT_SECONDS").as_deref(),
        "DB_IDLE_TIMEOUT_SECONDS",
        DEFAULT_IDLE_TIMEOUT_SECS,
    );
    let max_lifetime_secs = parse_pool_u64(
        lookup("DB_MAX_LIFETIME_SECONDS").as_deref(),
        "DB_MAX_LIFETIME_SECONDS",
        DEFAULT_MAX_LIFETIME_SECS,
    );

    // 启动期校验：拒绝明显无意义或危险的值，记录 warn 但不终止启动。
    let max_connections = if max_connections == 0 {
        tracing::warn!(
            "DB_MAX_CONNECTIONS=0 is invalid; using default {}",
            DEFAULT_MAX_CONNECTIONS
        );
        DEFAULT_MAX_CONNECTIONS
    } else {
        max_connections
    };

    // acquire_timeout=0 在 sqlx 里意味着"立即超时"，会让几乎所有请求失败。
    let acquire_timeout_secs = if acquire_timeout_secs == 0 {
        tracing::warn!(
            "DB_ACQUIRE_TIMEOUT_SECONDS=0 would cause immediate timeouts; using default {}s",
            DEFAULT_ACQUIRE_TIMEOUT_SECS
        );
        DEFAULT_ACQUIRE_TIMEOUT_SECS
    } else {
        // 超过 60s 的 acquire_timeout 会在连接池耗尽时导致请求长时间阻塞，触发级联故障。
        // 仍然接受该值（运维可能有意为之），但必须明确记录。
        if acquire_timeout_secs > 60 {
            tracing::warn!(
                "DB_ACQUIRE_TIMEOUT_SECONDS={} exceeds 60s; this may cause cascading failures under load",
                acquire_timeout_secs
            );
        }
        acquire_timeout_secs
    };

    PoolSettings {
        max_connections,
        acquire_timeout: Duration::from_secs(acquire_timeout_secs),
        idle_timeout: Duration::from_secs(idle_timeout_secs),
        max_lifetime: Duration::from_secs(max_lifetime_secs),
    }
}

/// 从可选原始字符串解析 u32，解析失败时 warn 并返回默认值。
fn parse_pool_u32(raw: Option<&str>, name: &'static str, default: u32) -> u32 {
    let Some(raw) = raw else {
        return default;
    };
    match raw.trim().parse::<u32>() {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!(
                "{}={:?} is not a valid u32; using default {}",
                name,
                raw,
                default
            );
            default
        }
    }
}

/// 从可选原始字符串解析 u64，解析失败时 warn 并返回默认值。
fn parse_pool_u64(raw: Option<&str>, name: &'static str, default: u64) -> u64 {
    let Some(raw) = raw else {
        return default;
    };
    match raw.trim().parse::<u64>() {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!(
                "{}={:?} is not a valid u64; using default {}",
                name,
                raw,
                default
            );
            default
        }
    }
}

pub fn connect(config: &Config) -> Result<Database, crate::sqlx::Error> {
    let settings = pool_settings_from_env();
    PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .acquire_timeout(settings.acquire_timeout)
        .idle_timeout(settings.idle_timeout)
        .max_lifetime(settings.max_lifetime)
        .connect_lazy(&config.database_url)
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
    ];

    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{normalize_migration_sql, pool_settings_from_lookup};

    // 辅助：构造一个总是返回 None 的 lookup（模拟所有变量未设置）
    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn migration_sql_normalizes_windows_line_endings() {
        assert_eq!(
            normalize_migration_sql("CREATE TABLE test;\r\n"),
            "CREATE TABLE test;\n"
        );
    }

    #[test]
    fn pool_settings_defaults_when_unset() {
        let s = pool_settings_from_lookup(no_env);
        assert_eq!(s.max_connections, 10);
        assert_eq!(s.acquire_timeout, Duration::from_secs(5));
        assert_eq!(s.idle_timeout, Duration::from_secs(600));
        assert_eq!(s.max_lifetime, Duration::from_secs(1800));
    }

    #[test]
    fn pool_settings_parses_valid_values() {
        let s = pool_settings_from_lookup(|key| match key {
            "DB_MAX_CONNECTIONS" => Some("20".into()),
            "DB_ACQUIRE_TIMEOUT_SECONDS" => Some("10".into()),
            "DB_IDLE_TIMEOUT_SECONDS" => Some("300".into()),
            "DB_MAX_LIFETIME_SECONDS" => Some("900".into()),
            _ => None,
        });
        assert_eq!(s.max_connections, 20);
        assert_eq!(s.acquire_timeout, Duration::from_secs(10));
        assert_eq!(s.idle_timeout, Duration::from_secs(300));
        assert_eq!(s.max_lifetime, Duration::from_secs(900));
    }

    #[test]
    fn pool_settings_fallback_on_invalid_string() {
        // 解析失败（非数字）时回退默认值
        let s = pool_settings_from_lookup(|key| match key {
            "DB_MAX_CONNECTIONS" => Some("abc".into()),
            "DB_ACQUIRE_TIMEOUT_SECONDS" => Some("not-a-number".into()),
            _ => None,
        });
        assert_eq!(s.max_connections, 10);
        assert_eq!(s.acquire_timeout, Duration::from_secs(5));
    }

    #[test]
    fn pool_settings_fallback_on_zero_max_connections() {
        // 0 无意义，回退默认值
        let s = pool_settings_from_lookup(|key| {
            if key == "DB_MAX_CONNECTIONS" {
                Some("0".into())
            } else {
                None
            }
        });
        assert_eq!(s.max_connections, 10);
    }

    #[test]
    fn pool_settings_fallback_on_zero_acquire_timeout() {
        // acquire_timeout=0 会导致立即超时，回退默认值
        let s = pool_settings_from_lookup(|key| {
            if key == "DB_ACQUIRE_TIMEOUT_SECONDS" {
                Some("0".into())
            } else {
                None
            }
        });
        assert_eq!(s.acquire_timeout, Duration::from_secs(5));
    }

    #[test]
    fn pool_settings_accepts_large_acquire_timeout_with_warning() {
        // 超过 60s 仍被接受（运维可能有意为之），只记录 warn
        let s = pool_settings_from_lookup(|key| {
            if key == "DB_ACQUIRE_TIMEOUT_SECONDS" {
                Some("120".into())
            } else {
                None
            }
        });
        assert_eq!(s.acquire_timeout, Duration::from_secs(120));
    }
}
