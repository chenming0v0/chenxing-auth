use std::{env, num::ParseIntError};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use super::{AuthEncryptionKey, ConfigError};

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
