//! PostgreSQL 连接池参数与每连接会话设置。
//!
//! 这里解决两件独立的事：
//!
//! 1. 池容量与等待行为（`max_connections` / `acquire_timeout` / 回收策略）。
//! 2. 服务端语句上限 `statement_timeout`（Issue #267）。
//!
//! 第二点是安全边界而不是性能调优：没有 `statement_timeout` 时，一条被锁住或走
//! 错执行计划的查询会一直占着连接，直到客户端断开。认证服务的池只有个位数连接，
//! 几条这样的查询就能把池抽干，让登录、令牌签发和 Discovery 一起挂掉。HTTP 层的
//! `request_timeout_seconds` 只切断响应，PostgreSQL 后端仍在跑，连接不会归还。
//! 上限必须由数据库自己执行。

use std::time::Duration;

/// 池的用途。决定是否施加 `statement_timeout`。
///
/// 迁移和归档必须走 [`PoolRole::Maintenance`]：`CREATE INDEX`、大表回填和审计归档
/// 的正常耗时可以远超任何适合请求路径的上限，被 `statement_timeout` 掐断会留下
/// 半完成的迁移状态。请求路径与维护路径因此使用彼此独立的连接池，各自的上限互不
/// 影响。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolRole {
    /// HTTP 请求路径使用的应用查询池，施加 `statement_timeout`。
    Application,
    /// 迁移与显式维护命令使用的池，不施加 `statement_timeout`。
    Maintenance,
}

/// 连接池参数，从环境变量读取。
/// 后续应收敛进 AppConfig，当前为避免并发改动冲突而就地读取。
#[derive(Debug)]
pub(crate) struct PoolSettings {
    pub(crate) max_connections: u32,
    pub(crate) acquire_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) max_lifetime: Duration,
    /// 应用池每条连接的 `statement_timeout`。`None` 表示运维显式关闭
    /// （`DB_STATEMENT_TIMEOUT_MS=0`），由数据库角色或代理层自行兜底。
    pub(crate) statement_timeout: Option<Duration>,
}

/// `DB_STATEMENT_TIMEOUT_MS` 解析失败。
///
/// 与池容量参数不同，这个值解析失败时不回退默认值：静默回退会让运维以为自己配置
/// 的上限生效，而真实上限是别的数字。宁可启动失败。
///
/// 越界只有一个变体：对运维来说"太小"和"太大"要看的是同一条信息——你给了什么值、
/// 允许的区间是什么。分成两个变体只会让调用方多一处 match 分支。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PoolSettingsError {
    #[error(
        "DB_STATEMENT_TIMEOUT_MS must be an integer number of milliseconds (0 disables the timeout)"
    )]
    StatementTimeoutNotAnInteger,
    #[error(
        "DB_STATEMENT_TIMEOUT_MS={value} is outside the accepted range {min}..={max} \
         milliseconds; use 0 to disable the timeout, or move long-running work to the \
         maintenance pool"
    )]
    StatementTimeoutOutOfRange { value: u64, min: u64, max: u64 },
}

const DEFAULT_MAX_CONNECTIONS: u32 = 10;
const DEFAULT_ACQUIRE_TIMEOUT_SECS: u64 = 5;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 600;
const DEFAULT_MAX_LIFETIME_SECS: u64 = 1800;

/// 应用池默认语句上限。
///
/// 5s 是保守值：请求路径上的查询都是主键或唯一索引点查、小批量列表和单行写入，
/// 正常耗时在毫秒级。留出三个数量级的余量，能容忍冷缓存、检查点抖动和管理端搜索，
/// 同时仍然远小于连接被长期占用所需的时间。默认值也小于 `request_timeout_seconds`
/// 的 30s，保证数据库先放弃，连接能归还给池。
const DEFAULT_STATEMENT_TIMEOUT_MS: u64 = 5_000;

/// 允许的最小语句上限。低于 100ms 会开始误杀正常查询。
const MIN_STATEMENT_TIMEOUT_MS: u64 = 100;

/// 允许的最大语句上限。超过 60s 的工作应该走维护池而不是请求路径。
const MAX_STATEMENT_TIMEOUT_MS: u64 = 60_000;

/// 从环境变量解析连接池参数。
pub(crate) fn pool_settings_from_env() -> Result<PoolSettings, PoolSettingsError> {
    pool_settings_from_lookup(|key| std::env::var(key).ok())
}

/// 连接池参数解析核心逻辑，接受任意 lookup 函数，方便单元测试。
///
/// 默认值依据：
/// - `max_connections = 10`：向后兼容，不改变现有部署行为。
/// - `acquire_timeout = 5s`：认证服务要求快速失败；sqlx 默认 30s 会在连接耗尽时
///   导致请求长时间阻塞，触发级联故障。5s 足以覆盖正常连接建立 + 池等待。
/// - `idle_timeout = 600s`：定期回收空闲连接，避免数据库端关闭连接后复用失效。
/// - `max_lifetime = 1800s`（30 分钟）：让连接定期轮换，消除长连接累积的服务端
///   状态，并在数据库主从切换后自然重连。
/// - `statement_timeout = 5000ms`：见 [`DEFAULT_STATEMENT_TIMEOUT_MS`]。
///
/// 容量类参数解析失败时 warn 并回退默认值（历史行为，不破坏现有部署）；
/// `DB_STATEMENT_TIMEOUT_MS` 解析失败时返回错误。
pub(crate) fn pool_settings_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<PoolSettings, PoolSettingsError> {
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
    let statement_timeout = parse_statement_timeout(lookup("DB_STATEMENT_TIMEOUT_MS").as_deref())?;

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

    Ok(PoolSettings {
        max_connections,
        acquire_timeout: Duration::from_secs(acquire_timeout_secs),
        idle_timeout: Duration::from_secs(idle_timeout_secs),
        max_lifetime: Duration::from_secs(max_lifetime_secs),
        statement_timeout,
    })
}

/// 解析 `DB_STATEMENT_TIMEOUT_MS`。
///
/// 边界与语义：
/// - 未设置 → 默认 [`DEFAULT_STATEMENT_TIMEOUT_MS`]。
/// - `0` → 显式关闭，返回 `None`。这是运维已在数据库角色上设置
///   `ALTER ROLE ... SET statement_timeout` 时唯一正当的选择，会记录 warn。
/// - `[MIN, MAX]` 之外 → 错误，不回退。
/// - 非整数 → 错误，不回退。
fn parse_statement_timeout(raw: Option<&str>) -> Result<Option<Duration>, PoolSettingsError> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Some(Duration::from_millis(DEFAULT_STATEMENT_TIMEOUT_MS)));
    };

    let value = raw
        .parse::<u64>()
        .map_err(|_| PoolSettingsError::StatementTimeoutNotAnInteger)?;

    if value == 0 {
        tracing::warn!(
            "DB_STATEMENT_TIMEOUT_MS=0 disables the server-side statement timeout; \
             a stuck query can now hold a pool connection indefinitely"
        );
        return Ok(None);
    }
    if !(MIN_STATEMENT_TIMEOUT_MS..=MAX_STATEMENT_TIMEOUT_MS).contains(&value) {
        return Err(PoolSettingsError::StatementTimeoutOutOfRange {
            value,
            min: MIN_STATEMENT_TIMEOUT_MS,
            max: MAX_STATEMENT_TIMEOUT_MS,
        });
    }
    Ok(Some(Duration::from_millis(value)))
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{PoolSettingsError, pool_settings_from_lookup};

    // 辅助：构造一个总是返回 None 的 lookup（模拟所有变量未设置）
    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn only(name: &'static str, value: &'static str) -> impl Fn(&str) -> Option<String> {
        move |key| (key == name).then(|| value.to_owned())
    }

    #[test]
    fn pool_settings_defaults_when_unset() {
        let s = pool_settings_from_lookup(no_env).expect("defaults are valid");
        assert_eq!(s.max_connections, 10);
        assert_eq!(s.acquire_timeout, Duration::from_secs(5));
        assert_eq!(s.idle_timeout, Duration::from_secs(600));
        assert_eq!(s.max_lifetime, Duration::from_secs(1800));
        assert_eq!(s.statement_timeout, Some(Duration::from_millis(5_000)));
    }

    #[test]
    fn pool_settings_parses_valid_values() {
        let s = pool_settings_from_lookup(|key| match key {
            "DB_MAX_CONNECTIONS" => Some("20".into()),
            "DB_ACQUIRE_TIMEOUT_SECONDS" => Some("10".into()),
            "DB_IDLE_TIMEOUT_SECONDS" => Some("300".into()),
            "DB_MAX_LIFETIME_SECONDS" => Some("900".into()),
            "DB_STATEMENT_TIMEOUT_MS" => Some("2500".into()),
            _ => None,
        })
        .expect("valid values");
        assert_eq!(s.max_connections, 20);
        assert_eq!(s.acquire_timeout, Duration::from_secs(10));
        assert_eq!(s.idle_timeout, Duration::from_secs(300));
        assert_eq!(s.max_lifetime, Duration::from_secs(900));
        assert_eq!(s.statement_timeout, Some(Duration::from_millis(2_500)));
    }

    #[test]
    fn pool_settings_fallback_on_invalid_string() {
        // 容量类参数解析失败（非数字）时回退默认值
        let s = pool_settings_from_lookup(|key| match key {
            "DB_MAX_CONNECTIONS" => Some("abc".into()),
            "DB_ACQUIRE_TIMEOUT_SECONDS" => Some("not-a-number".into()),
            _ => None,
        })
        .expect("capacity parse failures fall back");
        assert_eq!(s.max_connections, 10);
        assert_eq!(s.acquire_timeout, Duration::from_secs(5));
    }

    #[test]
    fn pool_settings_fallback_on_zero_max_connections() {
        // 0 无意义，回退默认值
        let s = pool_settings_from_lookup(only("DB_MAX_CONNECTIONS", "0")).expect("falls back");
        assert_eq!(s.max_connections, 10);
    }

    #[test]
    fn pool_settings_fallback_on_zero_acquire_timeout() {
        // acquire_timeout=0 会导致立即超时，回退默认值
        let s = pool_settings_from_lookup(only("DB_ACQUIRE_TIMEOUT_SECONDS", "0"))
            .expect("falls back");
        assert_eq!(s.acquire_timeout, Duration::from_secs(5));
    }

    #[test]
    fn pool_settings_accepts_large_acquire_timeout_with_warning() {
        // 超过 60s 仍被接受（运维可能有意为之），只记录 warn
        let s = pool_settings_from_lookup(only("DB_ACQUIRE_TIMEOUT_SECONDS", "120"))
            .expect("accepted with warning");
        assert_eq!(s.acquire_timeout, Duration::from_secs(120));
    }

    #[test]
    fn statement_timeout_accepts_boundary_values() {
        let min = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", "100"))
            .expect("minimum is inclusive");
        assert_eq!(min.statement_timeout, Some(Duration::from_millis(100)));

        let max = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", "60000"))
            .expect("maximum is inclusive");
        assert_eq!(max.statement_timeout, Some(Duration::from_millis(60_000)));
    }

    #[test]
    fn statement_timeout_zero_disables_explicitly() {
        // 0 是运维显式关闭，不是错误；语义与 PostgreSQL 一致。
        let s = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", "0"))
            .expect("zero is an explicit opt-out");
        assert_eq!(s.statement_timeout, None);
    }

    #[test]
    fn statement_timeout_ignores_surrounding_whitespace() {
        let s = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", "  1500  "))
            .expect("trimmed value parses");
        assert_eq!(s.statement_timeout, Some(Duration::from_millis(1_500)));
    }

    #[test]
    fn statement_timeout_empty_value_uses_default() {
        // 空字符串等同于未设置，避免 `DB_STATEMENT_TIMEOUT_MS=` 静默关闭上限。
        let s = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", "   "))
            .expect("empty value falls back to default");
        assert_eq!(s.statement_timeout, Some(Duration::from_millis(5_000)));
    }

    #[test]
    fn statement_timeout_rejects_non_integer() {
        // 不回退默认值：静默回退会让运维误以为自己的值生效。
        let error = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", "5s"))
            .expect_err("non-integer must fail startup");
        assert_eq!(error, PoolSettingsError::StatementTimeoutNotAnInteger);
    }

    #[test]
    fn statement_timeout_rejects_negative_value() {
        let error = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", "-1"))
            .expect_err("negative must fail startup");
        assert_eq!(error, PoolSettingsError::StatementTimeoutNotAnInteger);
    }

    #[test]
    fn statement_timeout_rejects_value_below_minimum() {
        let error = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", "99"))
            .expect_err("below minimum must fail startup");
        assert_eq!(
            error,
            PoolSettingsError::StatementTimeoutOutOfRange {
                value: 99,
                min: 100,
                max: 60_000,
            }
        );
    }

    #[test]
    fn statement_timeout_rejects_value_above_maximum() {
        let error = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", "60001"))
            .expect_err("above maximum must fail startup");
        assert_eq!(
            error,
            PoolSettingsError::StatementTimeoutOutOfRange {
                value: 60_001,
                min: 100,
                max: 60_000,
            }
        );
    }

    #[test]
    fn statement_timeout_rejects_value_exceeding_u64() {
        // u64::MAX + 1：溢出走的是同一条"不是整数"路径，不会被当成合法上限。
        let overflow = "18446744073709551616";
        let error = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", overflow))
            .expect_err("overflow must fail startup");
        assert_eq!(error, PoolSettingsError::StatementTimeoutNotAnInteger);
    }

    #[test]
    fn statement_timeout_errors_do_not_leak_credentials() {
        // 错误消息只能提到变量名和数值，不能带上 DATABASE_URL 之类的内容。
        let error = pool_settings_from_lookup(only("DB_STATEMENT_TIMEOUT_MS", "abc"))
            .expect_err("non-integer must fail startup")
            .to_string();
        assert!(error.contains("DB_STATEMENT_TIMEOUT_MS"));
        assert!(!error.contains("postgres://"));
    }
}
