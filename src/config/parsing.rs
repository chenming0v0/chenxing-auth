use std::{env, fmt, num::ParseIntError};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use super::ConfigError;

// ── 暴露给 state / oauth 模块使用的加密 key 类型 ──────────────────────────────

#[derive(Clone)]
pub struct AuthEncryptionKey([u8; 32]);

impl AuthEncryptionKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AuthEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthEncryptionKey(REDACTED)")
    }
}

#[derive(Clone)]
pub struct AuthEncryptionKeyRing {
    active_kid: String,
    keys: Vec<(String, AuthEncryptionKey)>,
}

impl AuthEncryptionKeyRing {
    pub fn single(key: AuthEncryptionKey) -> Self {
        Self {
            active_kid: "legacy".to_owned(),
            keys: vec![("legacy".to_owned(), key)],
        }
    }

    pub fn from_entries(
        active_kid: String,
        keys: Vec<(String, AuthEncryptionKey)>,
    ) -> Result<Self, ConfigError> {
        if keys.is_empty()
            || active_kid.trim().is_empty()
            || active_kid.len() > 64
            || keys.iter().any(|(kid, _)| kid.is_empty() || kid.len() > 64)
            || keys
                .iter()
                .enumerate()
                .any(|(i, (kid, _))| keys[..i].iter().any(|(known, _)| known == kid))
            || !keys.iter().any(|(kid, _)| kid == &active_kid)
        {
            return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
        }
        Ok(Self { active_kid, keys })
    }

    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }

    pub fn active_key(&self) -> &AuthEncryptionKey {
        self.key(&self.active_kid)
            .expect("active key must exist in a validated key ring")
    }

    pub fn key(&self, kid: &str) -> Option<&AuthEncryptionKey> {
        self.keys
            .iter()
            .find_map(|(stored, key)| (stored == kid).then_some(key))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &AuthEncryptionKey)> {
        self.keys.iter().map(|(kid, key)| (kid.as_str(), key))
    }
}

impl fmt::Debug for AuthEncryptionKeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthEncryptionKeyRing")
            .field("active_kid", &self.active_kid)
            .field(
                "kids",
                &self.keys.iter().map(|(kid, _)| kid).collect::<Vec<_>>(),
            )
            .finish()
    }
}

// ── 解析辅助函数 ──────────────────────────────────────────────────────────────

pub(super) fn parse_auth_encryption_key(value: &str) -> Result<AuthEncryptionKey, ConfigError> {
    let decoded = BASE64
        .decode(value.trim())
        .map_err(|_| ConfigError::InvalidValue("AUTH_ENCRYPTION_KEY"))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ConfigError::InvalidValue("AUTH_ENCRYPTION_KEY"))?;
    Ok(AuthEncryptionKey::new(bytes))
}

pub(super) fn required_env(name: &'static str) -> Result<String, ConfigError> {
    let value = env::var(name).map_err(|_| ConfigError::MissingValue(name))?;
    if value.trim().is_empty() {
        return Err(ConfigError::MissingValue(name));
    }
    Ok(value)
}

pub(super) fn parse_u16(name: &'static str, value: &str) -> Result<u16, ConfigError> {
    value
        .parse()
        .map_err(|source: ParseIntError| ConfigError::InvalidInteger { name, source })
}

pub(super) fn parse_u64(name: &'static str, value: &str) -> Result<u64, ConfigError> {
    value
        .parse()
        .map_err(|source: ParseIntError| ConfigError::InvalidInteger { name, source })
}

pub(super) fn parse_bool(name: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(ConfigError::InvalidValue(name)),
    }
}

/// 读取可选的无符号整数配置项，缺失或全空白时回退到 `default`。
///
/// 非数字取值仍然报错而不是静默回退：把 `ACCESS_TOKEN_TTL_SECONDS=1h` 之类的
/// 拼写错误当成默认值，运维会以为配置已生效，属于最难排查的一类故障。
pub(super) fn optional_u64(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    parse_optional(name, env::var(name).ok().as_deref(), default)
}

pub(super) fn optional_u32(name: &'static str, default: u32) -> Result<u32, ConfigError> {
    parse_optional(name, env::var(name).ok().as_deref(), default)
}

pub(super) fn optional_i64(name: &'static str, default: i64) -> Result<i64, ConfigError> {
    parse_optional(name, env::var(name).ok().as_deref(), default)
}

/// `optional_*` 的纯函数内核。取值作为参数传入而不是自己读进程环境，
/// 这样单测无需 `env::set_var`——后者在并行测试下是数据竞争（Rust 2024 起需要 `unsafe`）。
fn parse_optional<T>(name: &'static str, value: Option<&str>, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr<Err = ParseIntError>,
{
    match value {
        Some(value) if !value.trim().is_empty() => value
            .trim()
            .parse()
            .map_err(|source| ConfigError::InvalidInteger { name, source }),
        _ => Ok(default),
    }
}

pub(super) fn parse_auth_encryption_key_ring() -> Result<AuthEncryptionKeyRing, ConfigError> {
    let Ok(value) = env::var("AUTH_ENCRYPTION_KEYS") else {
        return Ok(AuthEncryptionKeyRing::single(parse_auth_encryption_key(
            &required_env("AUTH_ENCRYPTION_KEY")?,
        )?));
    };
    let active_kid = env::var("AUTH_ENCRYPTION_ACTIVE_KID")
        .ok()
        .filter(|kid| !kid.trim().is_empty())
        .map(|kid| kid.trim().to_owned());
    parse_auth_encryption_key_ring_value(&value, active_kid.as_deref())
}

pub(crate) fn parse_auth_encryption_key_ring_value(
    value: &str,
    active_kid: Option<&str>,
) -> Result<AuthEncryptionKeyRing, ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
    }
    let mut keys = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        let Some(entry) = item.strip_prefix("kid=") else {
            return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
        };
        let Some((kid, encoded)) = entry.split_once(':') else {
            return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
        };
        let kid = kid.trim();
        if kid.is_empty()
            || kid.len() > 64
            || keys.iter().any(|(known, _): &(String, _)| known == kid)
            || encoded.trim().is_empty()
        {
            return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
        }
        let key = parse_auth_encryption_key(encoded)
            .map_err(|_| ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"))?;
        keys.push((kid.to_owned(), key));
    }
    let active_kid = active_kid
        .filter(|kid| !kid.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| keys[0].0.clone());
    if !keys.iter().any(|(kid, _)| kid == &active_kid) {
        return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_ACTIVE_KID"));
    }
    AuthEncryptionKeyRing::from_entries(active_kid, keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 拼写错误必须报错。静默当成默认值会让运维以为配置已生效（最难排查的一类故障）。
    #[test]
    fn non_numeric_values_are_rejected() {
        for value in ["not-a-number", "1h", "3600s", "1_000"] {
            let error = parse_optional::<u64>("ACCESS_TOKEN_TTL_SECONDS", Some(value), 7)
                .expect_err("must reject");
            assert!(
                matches!(error, ConfigError::InvalidInteger { name, .. } if name == "ACCESS_TOKEN_TTL_SECONDS"),
                "value = {value}"
            );
        }
    }

    #[test]
    fn unset_or_blank_falls_back_to_the_default() {
        assert_eq!(parse_optional("X", None, 11_u64), Ok(11));
        assert_eq!(parse_optional("X", Some(""), 11_u64), Ok(11));
        assert_eq!(parse_optional("X", Some("   "), 11_u64), Ok(11));
    }

    #[test]
    fn valid_values_are_parsed_and_trimmed() {
        assert_eq!(parse_optional("X", Some("42"), 1_u64), Ok(42));
        assert_eq!(parse_optional("X", Some(" 42 "), 1_u32), Ok(42));
        assert_eq!(parse_optional("X", Some("0"), 1_u64), Ok(0));
        assert_eq!(parse_optional("X", Some("-5"), 1_i64), Ok(-5));
    }

    /// 超出目标类型范围时报错，而不是回绕成一个看似合法的小数值。
    #[test]
    fn out_of_range_values_are_rejected() {
        let error = parse_optional::<u32>("UNAUTHENTICATED_SOURCE_QPS", Some("4294967296"), 30)
            .expect_err("must reject overflow");
        assert!(matches!(error, ConfigError::InvalidInteger { .. }));
        assert!(parse_optional::<u64>("X", Some("-1"), 1).is_err());
    }
}
