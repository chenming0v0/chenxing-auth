use super::ConfigError;

pub const DEFAULT_KEY_ROTATION_GRACE_SECONDS: u64 = crate::keys::DEFAULT_KEY_RETENTION_SECONDS;
pub const DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS: u64 =
    crate::keys::DEFAULT_KEY_RETENTION_SKEW_ALLOWANCE_SECONDS;
pub const DEFAULT_KEY_ACTIVATION_DELAY_SECONDS: u64 =
    crate::keys::DEFAULT_KEY_ACTIVATION_DELAY_SECONDS;
pub const MIN_PRODUCTION_KEY_ACTIVATION_DELAY_SECONDS: u64 = DEFAULT_KEY_ACTIVATION_DELAY_SECONDS;
pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 3_600;

const MIN_KEY_ROTATION_GRACE_SECONDS: u64 = 1;
const MAX_KEY_ROTATION_GRACE_SECONDS: u64 = 30 * 24 * 60 * 60;
const MIN_TOKEN_TTL_SECONDS: u64 = 1;
const MAX_TOKEN_TTL_SECONDS: u64 = 24 * 60 * 60;

/// 会话绝对 TTL 上界（秒），#365。
///
/// 该值同时决定 Redis 会话键的 TTL 与撤销 tombstone 的存活时长
/// （`SessionStore::revocation_ttl_seconds`），并会原样送进 Redis
/// `SET ... EX`——Redis 整数上限是 i64，超限即报 `ERR invalid expire time`，
/// 每次登录/会话写入都会失败。默认 7 天，90 天已远超任何真实部署需要；
/// 更长只会拉长「被盗 Cookie 依然有效」的窗口和撤销标记的驻留时间。
pub const MAX_SESSION_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;

/// 会话空闲超时上界（秒），#365。
///
/// idle 截止永远不能越过绝对 TTL，超过 30 天与绝对期限相比已是死配置；
/// 且它参与 Redis 键 TTL 的 min 计算，同样受 Redis i64 上限约束。
pub const MAX_SESSION_IDLE_TIMEOUT_SECONDS: u64 = 30 * 24 * 60 * 60;

/// 单用户最大并发会话数上界（个），#365。
///
/// 默认 5，上界取 1000：每个会话都是一行 PostgreSQL 记录 + 一条 Redis 键 +
/// 一条 outbox 记录，无界配置会让脚本化登录无限堆叠会话，1000 已远超任何
/// 真人设备组合。
pub const MAX_SESSION_MAX_CONCURRENT_SESSIONS: u64 = 1_000;

fn validate_range(
    name: &'static str,
    value: u64,
    minimum: u64,
    maximum: u64,
) -> Result<(), ConfigError> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::InvalidValue(name))
    }
}

pub(super) fn validate_token_and_key_lifetimes(
    key_rotation_grace_seconds: u64,
    key_rotation_skew_allowance_seconds: u64,
    access_token_ttl_seconds: u64,
    id_token_ttl_seconds: u64,
) -> Result<(), ConfigError> {
    validate_range(
        "KEY_ROTATION_GRACE_SECONDS",
        key_rotation_grace_seconds,
        MIN_KEY_ROTATION_GRACE_SECONDS,
        MAX_KEY_ROTATION_GRACE_SECONDS,
    )?;
    // Issues #316/#546：同一容忍值保护旧 key 回收和新 key 激活。允许为 0
    // （单实例部署没有跨实例偏差）；上限是保留窗口本身——再大说明运维对时钟
    // 失准的预期比密钥保留期还长，基本是配置笔误，拒绝而不是静默接受。
    validate_range(
        "KEY_ROTATION_SKEW_ALLOWANCE_SECONDS",
        key_rotation_skew_allowance_seconds,
        0,
        key_rotation_grace_seconds,
    )?;
    validate_range(
        "ACCESS_TOKEN_TTL_SECONDS",
        access_token_ttl_seconds,
        MIN_TOKEN_TTL_SECONDS,
        MAX_TOKEN_TTL_SECONDS,
    )?;
    validate_range(
        "ID_TOKEN_TTL_SECONDS",
        id_token_ttl_seconds,
        MIN_TOKEN_TTL_SECONDS,
        MAX_TOKEN_TTL_SECONDS,
    )?;

    // 旧 key 签发的令牌必须在过期前一直可验证。
    //
    // 这条比较只在保留窗口从**退役时刻**起算时才成立（Issue #298）：令牌最迟在退役
    // 那一刻签发，`exp` 因此不晚于 `retired_at + max_token_ttl`，而公钥保留到
    // `retired_at + grace`。窗口起点若是创建时刻，长期在役的 key 会在轮换瞬间就越过
    // 窗口，`grace >= max_token_ttl` 无法保证任何事情。
    if key_rotation_grace_seconds < access_token_ttl_seconds.max(id_token_ttl_seconds) {
        return Err(ConfigError::InvalidValue("KEY_ROTATION_GRACE_SECONDS"));
    }
    Ok(())
}

/// 新公钥进入 JWKS 之后、接管签发之前的等待（Issue #454）。
///
/// 公共构造边界允许 0，供不读取环境变量的测试构造器立即激活。生产 `from_env`
/// 还会调用 [`validate_production_activation_delay`] 强制覆盖 JWKS 缓存和同步窗口。
/// 上界取 `300` 与保留窗口的较小值。
pub(super) fn validate_activation_delay(
    key_activation_delay_seconds: u64,
    key_rotation_grace_seconds: u64,
) -> Result<(), ConfigError> {
    let maximum = crate::keys::MAX_KEY_ACTIVATION_DELAY_SECONDS.min(key_rotation_grace_seconds);
    validate_range(
        "KEY_ACTIVATION_DELAY_SECONDS",
        key_activation_delay_seconds,
        0,
        maximum,
    )
}

pub(super) fn validate_production_activation_delay(
    key_activation_delay_seconds: u64,
    key_rotation_grace_seconds: u64,
) -> Result<(), ConfigError> {
    let maximum = crate::keys::MAX_KEY_ACTIVATION_DELAY_SECONDS.min(key_rotation_grace_seconds);
    validate_range(
        "KEY_ACTIVATION_DELAY_SECONDS",
        key_activation_delay_seconds,
        MIN_PRODUCTION_KEY_ACTIVATION_DELAY_SECONDS,
        maximum,
    )
}

/// 浏览器会话三参数的上下界校验（#365）。
///
/// 与 `validate_token_and_key_lifetimes` 一样拒绝而不是回退：这些项本就拒绝 0，
/// 越界同样是配置笔误，启动时报出配置项名，比错误拖到 Redis 调用时才暴露
/// （`ERR invalid expire time`）容易排查得多。
pub(super) fn validate_session_lifetimes(
    session_ttl_seconds: u64,
    session_idle_timeout_seconds: u64,
    session_max_concurrent_sessions: u64,
) -> Result<(), ConfigError> {
    validate_range(
        "SESSION_TTL_SECONDS",
        session_ttl_seconds,
        1,
        MAX_SESSION_TTL_SECONDS,
    )?;
    validate_range(
        "SESSION_IDLE_TIMEOUT_SECONDS",
        session_idle_timeout_seconds,
        1,
        MAX_SESSION_IDLE_TIMEOUT_SECONDS,
    )?;
    validate_range(
        "SESSION_MAX_CONCURRENT_SESSIONS",
        session_max_concurrent_sessions,
        1,
        MAX_SESSION_MAX_CONCURRENT_SESSIONS,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_defaults_and_boundaries_are_valid() {
        assert_eq!(
            DEFAULT_KEY_ROTATION_GRACE_SECONDS,
            crate::keys::DEFAULT_KEY_RETENTION_SECONDS
        );
        assert_eq!(
            DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
            crate::keys::DEFAULT_KEY_RETENTION_SKEW_ALLOWANCE_SECONDS
        );
        assert!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
            )
            .is_ok()
        );
        assert!(
            validate_token_and_key_lifetimes(
                MIN_KEY_ROTATION_GRACE_SECONDS,
                0,
                MIN_TOKEN_TTL_SECONDS,
                MIN_TOKEN_TTL_SECONDS,
            )
            .is_ok()
        );
        assert!(
            validate_token_and_key_lifetimes(
                MAX_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
                MAX_TOKEN_TTL_SECONDS,
                MAX_TOKEN_TTL_SECONDS,
            )
            .is_ok()
        );
    }

    #[test]
    fn zero_lifetimes_are_rejected_by_field() {
        assert_eq!(
            validate_token_and_key_lifetimes(
                0,
                DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
            ),
            Err(ConfigError::InvalidValue("KEY_ROTATION_GRACE_SECONDS"))
        );
        assert_eq!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
                0,
                DEFAULT_TOKEN_TTL_SECONDS,
            ),
            Err(ConfigError::InvalidValue("ACCESS_TOKEN_TTL_SECONDS"))
        );
        assert_eq!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
                0,
            ),
            Err(ConfigError::InvalidValue("ID_TOKEN_TTL_SECONDS"))
        );
    }

    #[test]
    fn excessive_lifetimes_are_rejected_by_field() {
        assert_eq!(
            validate_token_and_key_lifetimes(
                MAX_KEY_ROTATION_GRACE_SECONDS + 1,
                DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
            ),
            Err(ConfigError::InvalidValue("KEY_ROTATION_GRACE_SECONDS"))
        );
        assert_eq!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
                MAX_TOKEN_TTL_SECONDS + 1,
                DEFAULT_TOKEN_TTL_SECONDS,
            ),
            Err(ConfigError::InvalidValue("ACCESS_TOKEN_TTL_SECONDS"))
        );
        assert_eq!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
                MAX_TOKEN_TTL_SECONDS + 1,
            ),
            Err(ConfigError::InvalidValue("ID_TOKEN_TTL_SECONDS"))
        );
    }

    #[test]
    fn token_lifetimes_cannot_outlive_key_rotation_grace() {
        assert_eq!(
            validate_token_and_key_lifetimes(
                3_600,
                DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
                3_601,
                3_600,
            ),
            Err(ConfigError::InvalidValue("KEY_ROTATION_GRACE_SECONDS"))
        );
        assert_eq!(
            validate_token_and_key_lifetimes(
                3_600,
                DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
                3_600,
                3_601,
            ),
            Err(ConfigError::InvalidValue("KEY_ROTATION_GRACE_SECONDS"))
        );
    }

    /// Issue #316：跨实例时钟偏差容忍可关闭（单实例部署），但不能超过保留窗口
    /// 本身——容忍值大于窗口说明运维对时钟失准的预期比密钥保留期还长，是笔误。
    #[test]
    fn skew_allowance_must_not_exceed_the_rotation_grace_window() {
        assert!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                0,
                DEFAULT_TOKEN_TTL_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
            )
            .is_ok()
        );
        assert!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
            )
            .is_ok()
        );
        assert_eq!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_KEY_ROTATION_GRACE_SECONDS + 1,
                DEFAULT_TOKEN_TTL_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
            ),
            Err(ConfigError::InvalidValue(
                "KEY_ROTATION_SKEW_ALLOWANCE_SECONDS"
            ))
        );
    }

    #[test]
    fn activation_delay_is_bounded_by_cache_window_and_grace() {
        assert!(validate_activation_delay(0, DEFAULT_KEY_ROTATION_GRACE_SECONDS).is_ok());
        assert!(
            validate_activation_delay(
                DEFAULT_KEY_ACTIVATION_DELAY_SECONDS,
                DEFAULT_KEY_ROTATION_GRACE_SECONDS
            )
            .is_ok()
        );
        assert_eq!(
            validate_activation_delay(
                crate::keys::MAX_KEY_ACTIVATION_DELAY_SECONDS + 1,
                DEFAULT_KEY_ROTATION_GRACE_SECONDS
            ),
            Err(ConfigError::InvalidValue("KEY_ACTIVATION_DELAY_SECONDS"))
        );
        assert_eq!(
            validate_activation_delay(30, 10),
            Err(ConfigError::InvalidValue("KEY_ACTIVATION_DELAY_SECONDS"))
        );
        assert_eq!(
            validate_production_activation_delay(
                MIN_PRODUCTION_KEY_ACTIVATION_DELAY_SECONDS - 1,
                DEFAULT_KEY_ROTATION_GRACE_SECONDS
            ),
            Err(ConfigError::InvalidValue("KEY_ACTIVATION_DELAY_SECONDS"))
        );
        assert!(
            validate_production_activation_delay(
                MIN_PRODUCTION_KEY_ACTIVATION_DELAY_SECONDS,
                DEFAULT_KEY_ROTATION_GRACE_SECONDS
            )
            .is_ok()
        );
    }

    #[test]
    fn session_lifetimes_out_of_range_are_rejected_by_field() {
        assert_eq!(
            validate_session_lifetimes(0, 1_800, 5),
            Err(ConfigError::InvalidValue("SESSION_TTL_SECONDS"))
        );
        assert_eq!(
            validate_session_lifetimes(604_800, MAX_SESSION_IDLE_TIMEOUT_SECONDS + 1, 5),
            Err(ConfigError::InvalidValue("SESSION_IDLE_TIMEOUT_SECONDS"))
        );
        assert_eq!(
            validate_session_lifetimes(604_800, 1_800, MAX_SESSION_MAX_CONCURRENT_SESSIONS + 1),
            Err(ConfigError::InvalidValue("SESSION_MAX_CONCURRENT_SESSIONS"))
        );
        // 饱和值（#365 的原始利用形态）：u64::MAX 秒的 TTL 通过启动校验后会把
        // 超出 Redis i64 上限的 EX 送进 `SET ... EX`，每次会话写入都失败。
        assert_eq!(
            validate_session_lifetimes(u64::MAX, 1_800, 5),
            Err(ConfigError::InvalidValue("SESSION_TTL_SECONDS"))
        );
        assert_eq!(
            validate_session_lifetimes(604_800, u64::MAX, u64::MAX),
            Err(ConfigError::InvalidValue("SESSION_IDLE_TIMEOUT_SECONDS"))
        );
    }

    #[test]
    fn documented_session_defaults_and_boundaries_are_valid() {
        assert!(
            validate_session_lifetimes(604_800, 1_800, 5).is_ok(),
            "documented defaults must pass"
        );
        assert!(
            validate_session_lifetimes(
                MAX_SESSION_TTL_SECONDS,
                MAX_SESSION_IDLE_TIMEOUT_SECONDS,
                MAX_SESSION_MAX_CONCURRENT_SESSIONS,
            )
            .is_ok(),
            "the upper bounds themselves must be accepted"
        );
    }
}
