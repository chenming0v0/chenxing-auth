use std::env;

use super::{
    ConfigError,
    config_parsing::{parse_bool, parse_u64},
};

pub const DEFAULT_AUDIT_RETENTION_DAYS: i32 = 2_555;
const MAX_AUDIT_RETENTION_DAYS: u64 = 36_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditRetentionConfig {
    pub enabled: bool,
    pub retention_days: i32,
}

impl Default for AuditRetentionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_days: DEFAULT_AUDIT_RETENTION_DAYS,
        }
    }
}

pub(super) fn audit_retention_from_env() -> Result<AuditRetentionConfig, ConfigError> {
    let enabled = parse_bool(
        "AUDIT_ARCHIVE_ENABLED",
        env::var("AUDIT_ARCHIVE_ENABLED")
            .ok()
            .as_deref()
            .unwrap_or("false"),
    )?;
    let raw_retention_days = parse_u64(
        "AUDIT_RETENTION_DAYS",
        env::var("AUDIT_RETENTION_DAYS")
            .ok()
            .as_deref()
            .unwrap_or("2555"),
    )?;
    if !(1..=MAX_AUDIT_RETENTION_DAYS).contains(&raw_retention_days) {
        return Err(ConfigError::InvalidValue("AUDIT_RETENTION_DAYS"));
    }
    let retention_days = i32::try_from(raw_retention_days)
        .map_err(|_| ConfigError::InvalidValue("AUDIT_RETENTION_DAYS"))?;
    Ok(AuditRetentionConfig {
        enabled,
        retention_days,
    })
}
