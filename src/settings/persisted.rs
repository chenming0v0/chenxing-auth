//! 持久化 JSON 设置的统一 decode / schema 升级管道。
//!
//! Passkey、email policy 和 security limits 同属 `app_settings` JSON。这里只处理
//! 空值、旧字段形状和未知 schema；取值合法性交给各类型的 `validate()`。
//! 热路径走 [`PersistedDecode::require`]（fail-closed），管理读取走
//! [`PersistedDecode::inspect`]（可编辑值 + 诊断）。

use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{
    EMAIL_POLICY_KEY, PASSKEY_KEY, SECURITY_LIMITS_KEY, SecurityLimitsSetting,
    domain::{EmailPolicySetting, PasskeySetting, SettingsValidationError},
};

/// 一次 decode + schema 升级的结果。尚未做取值校验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedDecode<T> {
    /// 没有行，或值为空白。管理员从未写过这份设置。
    Unconfigured,
    /// JSON 可识别，并已按兼容规则补全缺失字段。
    Decoded(T),
    /// 文本不是这份设置的可识别对象。
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

/// 管理读取看到的当前值，加上是否需要修复。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingInspection<T> {
    pub value: T,
    pub diagnostic: Option<SettingDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

/// 可从 `app_settings` JSON 还原的设置。
pub trait PersistedSetting: Sized + Default + DeserializeOwned {
    const KEY: &'static str;
    const KNOWN_FIELDS: &'static [&'static str];

    /// 把旧形状改成当前 schema。默认只原样返回；缺失字段由 `#[serde(default)]` 补。
    fn upgrade_schema(value: Value) -> Value {
        value
    }
}

pub fn decode_persisted<T: PersistedSetting>(raw: Option<&str>) -> PersistedDecode<T> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return PersistedDecode::Unconfigured;
    };
    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(value) => value,
        Err(error) => {
            return PersistedDecode::Corrupt(PersistedDecodeError::from_serde(
                error,
                PersistedDecodeKind::Json,
            ));
        }
    };
    if !parsed.is_object() {
        return PersistedDecode::Corrupt(PersistedDecodeError::structural(
            PersistedDecodeKind::NotAnObject,
        ));
    }
    let upgraded = T::upgrade_schema(parsed);
    if !upgraded.is_object() {
        return PersistedDecode::Corrupt(PersistedDecodeError::structural(
            PersistedDecodeKind::NotAnObject,
        ));
    }
    if !has_known_field(&upgraded, T::KNOWN_FIELDS) {
        return PersistedDecode::Corrupt(PersistedDecodeError::structural(
            PersistedDecodeKind::UnknownSchema,
        ));
    }
    match serde_json::from_value::<T>(upgraded) {
        Ok(value) => PersistedDecode::Decoded(value),
        Err(error) => PersistedDecode::Corrupt(PersistedDecodeError::from_serde(
            error,
            PersistedDecodeKind::TypeMismatch,
        )),
    }
}

impl<T> PersistedDecode<T> {
    /// 安全热路径：只交出通过校验的值。损坏或越界都不能用。
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

    /// 管理读取：尽量返回可编辑的当前值，坏数据变成诊断而不是 500。
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
    fn from_serde(error: serde_json::Error, kind: PersistedDecodeKind) -> Self {
        Self {
            line: error.line(),
            column: error.column(),
            kind,
        }
    }

    const fn structural(kind: PersistedDecodeKind) -> Self {
        Self {
            line: 0,
            column: 0,
            kind,
        }
    }
}

fn has_known_field(value: &Value, known: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| known.iter().any(|field| object.contains_key(*field)))
}

/// 旧数据或手工编辑里，列表字段有时会写成单个字符串。
fn upgrade_string_list(value: &mut Value, field: &str) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    let Some(text) = object.get(field).and_then(Value::as_str) else {
        return;
    };
    let items = text
        .split([',', ' ', '\n', '\r', '\t'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| Value::String((*part).to_owned()))
        .collect();
    object.insert(field.to_owned(), Value::Array(items));
}

impl PersistedSetting for PasskeySetting {
    const KEY: &'static str = PASSKEY_KEY;
    const KNOWN_FIELDS: &'static [&'static str] = &[
        "enabled",
        "rp_name",
        "rp_id",
        "user_verification",
        "authenticator_attachment",
        "allow_insecure_origin",
        "allowed_origins",
    ];

    fn upgrade_schema(mut value: Value) -> Value {
        upgrade_string_list(&mut value, "allowed_origins");
        value
    }
}

impl PersistedSetting for EmailPolicySetting {
    const KEY: &'static str = EMAIL_POLICY_KEY;
    const KNOWN_FIELDS: &'static [&'static str] = &[
        "whitelist_enabled",
        "alias_restriction_enabled",
        "allowed_domains",
    ];

    fn upgrade_schema(mut value: Value) -> Value {
        upgrade_string_list(&mut value, "allowed_domains");
        value
    }
}

impl PersistedSetting for SecurityLimitsSetting {
    const KEY: &'static str = SECURITY_LIMITS_KEY;
    const KNOWN_FIELDS: &'static [&'static str] = &[
        "unauthenticated_source_qps",
        "authorization_code_ttl_seconds",
        "pending_request_ttl_seconds",
        "max_pending_requests_per_client",
        "max_pending_requests_global",
        "auth_failure_window_seconds",
        "account_failure_limit",
        "ip_failure_limit",
        "totp_ticket_failure_limit",
        "external_login_state_ttl_seconds",
        "external_login_state_rate_window_seconds",
        "external_login_state_rate_limit",
        "external_login_state_max_pending",
    ];
}

#[cfg(test)]
#[path = "persisted_tests.rs"]
mod tests;
