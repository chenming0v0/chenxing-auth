use super::ConfigError;

pub const DEFAULT_KEY_ROTATION_GRACE_SECONDS: u64 = crate::keys::DEFAULT_KEY_RETENTION_SECONDS;
pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 3_600;

const MIN_KEY_ROTATION_GRACE_SECONDS: u64 = 1;
const MAX_KEY_ROTATION_GRACE_SECONDS: u64 = 30 * 24 * 60 * 60;
const MIN_TOKEN_TTL_SECONDS: u64 = 1;
const MAX_TOKEN_TTL_SECONDS: u64 = 24 * 60 * 60;

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
    access_token_ttl_seconds: u64,
    id_token_ttl_seconds: u64,
) -> Result<(), ConfigError> {
    validate_range(
        "KEY_ROTATION_GRACE_SECONDS",
        key_rotation_grace_seconds,
        MIN_KEY_ROTATION_GRACE_SECONDS,
        MAX_KEY_ROTATION_GRACE_SECONDS,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_defaults_and_boundaries_are_valid() {
        assert_eq!(
            DEFAULT_KEY_ROTATION_GRACE_SECONDS,
            crate::keys::DEFAULT_KEY_RETENTION_SECONDS
        );
        assert!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
            )
            .is_ok()
        );
        assert!(
            validate_token_and_key_lifetimes(
                MIN_KEY_ROTATION_GRACE_SECONDS,
                MIN_TOKEN_TTL_SECONDS,
                MIN_TOKEN_TTL_SECONDS,
            )
            .is_ok()
        );
        assert!(
            validate_token_and_key_lifetimes(
                MAX_KEY_ROTATION_GRACE_SECONDS,
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
                DEFAULT_TOKEN_TTL_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
            ),
            Err(ConfigError::InvalidValue("KEY_ROTATION_GRACE_SECONDS"))
        );
        assert_eq!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
                0,
                DEFAULT_TOKEN_TTL_SECONDS,
            ),
            Err(ConfigError::InvalidValue("ACCESS_TOKEN_TTL_SECONDS"))
        );
        assert_eq!(
            validate_token_and_key_lifetimes(
                DEFAULT_KEY_ROTATION_GRACE_SECONDS,
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
                DEFAULT_TOKEN_TTL_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
            ),
            Err(ConfigError::InvalidValue("KEY_ROTATION_GRACE_SECONDS"))
        );
        assert_eq!(
            validate_token_and_key_lifetimes(
                MAX_KEY_ROTATION_GRACE_SECONDS,
                MAX_TOKEN_TTL_SECONDS + 1,
                DEFAULT_TOKEN_TTL_SECONDS,
            ),
            Err(ConfigError::InvalidValue("ACCESS_TOKEN_TTL_SECONDS"))
        );
        assert_eq!(
            validate_token_and_key_lifetimes(
                MAX_KEY_ROTATION_GRACE_SECONDS,
                DEFAULT_TOKEN_TTL_SECONDS,
                MAX_TOKEN_TTL_SECONDS + 1,
            ),
            Err(ConfigError::InvalidValue("ID_TOKEN_TTL_SECONDS"))
        );
    }

    #[test]
    fn token_lifetimes_cannot_outlive_key_rotation_grace() {
        assert_eq!(
            validate_token_and_key_lifetimes(3_600, 3_601, 3_600),
            Err(ConfigError::InvalidValue("KEY_ROTATION_GRACE_SECONDS"))
        );
        assert_eq!(
            validate_token_and_key_lifetimes(3_600, 3_600, 3_601),
            Err(ConfigError::InvalidValue("KEY_ROTATION_GRACE_SECONDS"))
        );
    }
}
