//! `app_settings.setting_value` JSON 的回读入口（#449 / #448）。
//!
//! 管理 API 继续用领域类型的严格 Deserialize：缺字段就是 400，不能和回读
//! 共用 `#[serde(default)]`。否则 PUT 漏字段会按默认值覆盖已经收紧的阈值，
//! 等于在写路径上静默放宽安全边界。
//!
//! Decode / 升级（#449）：
//! - Passkey / SecurityLimits：用 `Default` 补缺失键，已写入的键原样保留。
//!   补的是当前安全默认值，不是类型零值。
//! - EmailPolicy：`whitelist_enabled` 缺失视为结构漂移，拒绝解析。
//!   `alias_restriction_enabled` / `allowed_domains` 可以缺，按 Default 补。
//!
//! 读意图（#448）只有两种，不要再加第三种：
//! - 热路径 [`PersistedDecode::require`]：校验失败或损坏 fail-closed。
//! - 管理读取 [`PersistedDecode::inspect`]：交出可编辑值 + 诊断。

use serde::Serialize;
use serde::de::{DeserializeOwned, Error as DeError};

use super::{
    EMAIL_POLICY_KEY, PASSKEY_KEY, REGISTRATION_SETTING_KEY, SECURITY_LIMITS_KEY,
    SESSION_LIFETIME_KEY, SecurityLimitsSetting, SessionLifetimeSetting,
    domain::{EmailPolicySetting, PasskeySetting, RegistrationSetting, SettingsValidationError},
};

pub fn parse_passkey(raw: &str) -> Result<PasskeySetting, serde_json::Error> {
    overlay_defaults(raw, &PasskeySetting::default())
}

pub fn parse_registration(raw: &str) -> Result<RegistrationSetting, serde_json::Error> {
    overlay_defaults(raw, &RegistrationSetting::default())
}

pub fn parse_email_policy(raw: &str) -> Result<EmailPolicySetting, serde_json::Error> {
    let stored: serde_json::Value = serde_json::from_str(raw)?;
    match &stored {
        serde_json::Value::Object(object) if object.contains_key("whitelist_enabled") => {
            overlay_value(stored, &EmailPolicySetting::default())
        }
        serde_json::Value::Object(_) => Err(DeError::custom(
            "stored email policy is missing whitelist_enabled",
        )),
        other => serde_json::from_value(other.clone()),
    }
}

pub fn parse_security_limits(raw: &str) -> Result<SecurityLimitsSetting, serde_json::Error> {
    overlay_defaults(raw, &SecurityLimitsSetting::default())
}

pub fn parse_session_lifetime(raw: &str) -> Result<SessionLifetimeSetting, serde_json::Error> {
    overlay_defaults(raw, &SessionLifetimeSetting::default())
}

fn overlay_defaults<T>(raw: &str, defaults: &T) -> Result<T, serde_json::Error>
where
    T: Serialize + DeserializeOwned,
{
    let stored: serde_json::Value = serde_json::from_str(raw)?;
    overlay_value(stored, defaults)
}

fn overlay_value<T>(stored: serde_json::Value, defaults: &T) -> Result<T, serde_json::Error>
where
    T: Serialize + DeserializeOwned,
{
    match stored {
        serde_json::Value::Object(overlay) => {
            let mut merged = serde_json::to_value(defaults).map_err(DeError::custom)?;
            if let serde_json::Value::Object(base) = &mut merged {
                for (key, value) in overlay {
                    base.insert(key, value);
                }
            }
            serde_json::from_value(merged)
        }
        other => serde_json::from_value(other),
    }
}

/// 一次 decode + schema 升级的结果。尚未做取值校验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedDecode<T> {
    Unconfigured,
    Decoded(T),
    Corrupt(PersistedDecodeError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedDecodeError {
    pub line: usize,
    pub column: usize,
    pub kind: PersistedDecodeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistedDecodeKind {
    Json,
    NotAnObject,
    UnknownSchema,
    TypeMismatch,
}

impl PersistedDecodeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::NotAnObject => "not_an_object",
            Self::UnknownSchema => "unknown_schema",
            Self::TypeMismatch => "type_mismatch",
        }
    }
}

impl std::fmt::Display for PersistedDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stored setting json is unreadable ({}) at {}:{}",
            self.kind.as_str(),
            self.line,
            self.column
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PersistedLoadError {
    Invalid(SettingsValidationError),
    Corrupt(PersistedDecodeError),
}

impl std::fmt::Display for PersistedLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(error) => write!(f, "{error}"),
            Self::Corrupt(error) => write!(f, "{error}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SettingInspection<T> {
    pub value: T,
    pub diagnostic: Option<SettingDiagnostic>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SettingDiagnostic {
    Invalid(SettingsValidationError),
    Corrupt,
}

impl std::fmt::Display for SettingDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(error) => write!(f, "invalid: {error}"),
            Self::Corrupt => f.write_str("stored json is unreadable"),
        }
    }
}

impl SettingDiagnostic {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid",
            Self::Corrupt => "corrupt",
        }
    }
}

pub trait PersistedSetting: Sized + Default {
    const KEY: &'static str;
    fn parse_stored(raw: &str) -> Result<Self, serde_json::Error>;
}

impl PersistedSetting for PasskeySetting {
    const KEY: &'static str = PASSKEY_KEY;
    fn parse_stored(raw: &str) -> Result<Self, serde_json::Error> {
        parse_passkey(raw)
    }
}

impl PersistedSetting for RegistrationSetting {
    const KEY: &'static str = REGISTRATION_SETTING_KEY;
    fn parse_stored(raw: &str) -> Result<Self, serde_json::Error> {
        parse_registration(raw)
    }
}

impl PersistedSetting for EmailPolicySetting {
    const KEY: &'static str = EMAIL_POLICY_KEY;
    fn parse_stored(raw: &str) -> Result<Self, serde_json::Error> {
        parse_email_policy(raw)
    }
}

impl PersistedSetting for SecurityLimitsSetting {
    const KEY: &'static str = SECURITY_LIMITS_KEY;
    fn parse_stored(raw: &str) -> Result<Self, serde_json::Error> {
        parse_security_limits(raw)
    }
}

impl PersistedSetting for SessionLifetimeSetting {
    const KEY: &'static str = SESSION_LIFETIME_KEY;
    fn parse_stored(raw: &str) -> Result<Self, serde_json::Error> {
        parse_session_lifetime(raw)
    }
}

pub fn decode_persisted<T: PersistedSetting>(raw: Option<&str>) -> PersistedDecode<T> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return PersistedDecode::Unconfigured;
    };
    match T::parse_stored(raw) {
        Ok(value) => PersistedDecode::Decoded(value),
        Err(error) => PersistedDecode::Corrupt(PersistedDecodeError::from_serde(error)),
    }
}

impl<T> PersistedDecode<T> {
    pub fn require(
        self,
        default: T,
        prepare: impl FnOnce(T) -> T,
        validate: impl FnOnce(T) -> Result<T, SettingsValidationError>,
    ) -> Result<T, PersistedLoadError> {
        let prepared = match self {
            Self::Unconfigured => prepare(default),
            Self::Decoded(value) => prepare(value),
            Self::Corrupt(error) => return Err(PersistedLoadError::Corrupt(error)),
        };
        validate(prepared).map_err(PersistedLoadError::Invalid)
    }

    pub fn inspect(
        self,
        default: T,
        prepare: impl FnOnce(T) -> T,
        validate: impl FnOnce(T) -> Result<T, SettingsValidationError>,
    ) -> SettingInspection<T>
    where
        T: Clone,
    {
        match self {
            Self::Corrupt(_) => SettingInspection {
                value: prepare(default),
                diagnostic: Some(SettingDiagnostic::Corrupt),
            },
            Self::Unconfigured => inspect_prepared(prepare(default), validate),
            Self::Decoded(value) => inspect_prepared(prepare(value), validate),
        }
    }
}

fn inspect_prepared<T: Clone>(
    prepared: T,
    validate: impl FnOnce(T) -> Result<T, SettingsValidationError>,
) -> SettingInspection<T> {
    match validate(prepared.clone()) {
        Ok(value) => SettingInspection {
            value,
            diagnostic: None,
        },
        Err(error) => SettingInspection {
            value: prepared,
            diagnostic: Some(SettingDiagnostic::Invalid(error)),
        },
    }
}

impl PersistedDecodeError {
    fn from_serde(error: serde_json::Error) -> Self {
        let kind = match error.classify() {
            serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                PersistedDecodeKind::Json
            }
            serde_json::error::Category::Data if error.line() == 0 && error.column() == 0 => {
                PersistedDecodeKind::UnknownSchema
            }
            serde_json::error::Category::Data => PersistedDecodeKind::TypeMismatch,
            serde_json::error::Category::Io => PersistedDecodeKind::NotAnObject,
        };
        Self {
            line: error.line(),
            column: error.column(),
            kind,
        }
    }
}

#[cfg(test)]
#[path = "persisted_tests.rs"]
mod tests;
