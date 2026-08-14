use serde::{Deserialize, Serialize};
use std::fmt;

use super::domain::SettingsValidationError;
use super::smtp_sender::parse_smtp_sender;

const MAX_SMTP_HOST_LENGTH: usize = 253;
const MAX_SMTP_USERNAME_LENGTH: usize = 256;
const MAX_SMTP_FROM_LENGTH: usize = 320;
const MAX_SMTP_PASSWORD_LENGTH: usize = 512;

/// SMTP 密码更新意图。管理 PUT 的主契约，不要再用空字符串猜 keep。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpPasswordAction {
    Keep,
    Set,
    Clear,
}

/// 校验通过后的密码变更。`Set` 持有明文，Debug 必须脱敏。
#[derive(Clone, PartialEq, Eq)]
pub enum SmtpPasswordUpdate {
    Keep,
    Set(String),
    Clear,
}

impl SmtpPasswordUpdate {
    pub const fn action(&self) -> SmtpPasswordAction {
        match self {
            Self::Keep => SmtpPasswordAction::Keep,
            Self::Set(_) => SmtpPasswordAction::Set,
            Self::Clear => SmtpPasswordAction::Clear,
        }
    }

    /// 把三态落到将要写入的密文：keep 复用旧值，set 加密替换，clear 删掉已存密文。
    pub(crate) fn next_ciphertext<E>(
        self,
        existing: Option<String>,
        encrypt: impl FnOnce(String) -> Result<String, E>,
    ) -> Result<Option<String>, E> {
        match self {
            Self::Keep => Ok(existing),
            Self::Set(password) => encrypt(password).map(Some),
            Self::Clear => Ok(None),
        }
    }
}

impl fmt::Debug for SmtpPasswordUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keep => f.write_str("Keep"),
            Self::Set(_) => f.write_str("Set(<redacted>)"),
            Self::Clear => f.write_str("Clear"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpSetting {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from_address: String,
    pub ssl_enabled: bool,
    pub force_auth_login: bool,
    pub password_configured: bool,
}

impl Default for SmtpSetting {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 587,
            username: String::new(),
            from_address: String::new(),
            ssl_enabled: true,
            force_auth_login: false,
            password_configured: false,
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct SmtpSettingUpdate {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from_address: String,
    pub ssl_enabled: bool,
    pub force_auth_login: bool,
    /// 省略时走兼容规则：无 `password` 为 keep，非空 `password` 为 set。
    #[serde(default)]
    pub password_action: Option<SmtpPasswordAction>,
    /// Write-only。只在 `set` 时提供明文；keep/clear 必须省略或 null。
    #[serde(default)]
    pub password: Option<String>,
}

impl fmt::Debug for SmtpSettingUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpSettingUpdate")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("from_address", &self.from_address)
            .field("ssl_enabled", &self.ssl_enabled)
            .field("force_auth_login", &self.force_auth_login)
            .field("password_action", &self.password_action)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredSmtpSetting {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from_address: String,
    pub ssl_enabled: bool,
    pub force_auth_login: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_ciphertext: Option<String>,
}

impl fmt::Debug for StoredSmtpSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredSmtpSetting")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("from_address", &self.from_address)
            .field("ssl_enabled", &self.ssl_enabled)
            .field("force_auth_login", &self.force_auth_login)
            .field(
                "password_ciphertext",
                &self.password_ciphertext.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl SmtpSettingUpdate {
    pub fn validate(self) -> Result<(SmtpSetting, SmtpPasswordUpdate), SettingsValidationError> {
        let host = self.host.trim().to_owned();
        if host.chars().count() > MAX_SMTP_HOST_LENGTH
            || (!host.is_empty()
                && (host.starts_with('.')
                    || host.ends_with('.')
                    || host.contains("..")
                    || !host.chars().all(|character| {
                        character.is_ascii_alphanumeric() || character == '-' || character == '.'
                    })))
        {
            return Err(SettingsValidationError::InvalidSmtpHost);
        }
        if self.port == 0 {
            return Err(SettingsValidationError::InvalidSmtpPort);
        }
        let username = self.username.trim().to_owned();
        if username.chars().count() > MAX_SMTP_USERNAME_LENGTH {
            return Err(SettingsValidationError::InvalidSmtpUsername);
        }
        let from_address = self.from_address.trim().to_owned();
        if self.from_address.chars().any(char::is_control)
            || from_address.chars().count() > MAX_SMTP_FROM_LENGTH
            || (!from_address.is_empty() && parse_smtp_sender(&from_address).is_none())
        {
            return Err(SettingsValidationError::InvalidSmtpFrom);
        }
        let password_update = resolve_password_update(self.password_action, self.password)?;
        Ok((
            SmtpSetting {
                host,
                port: self.port,
                username,
                from_address,
                ssl_enabled: self.ssl_enabled,
                force_auth_login: self.force_auth_login,
                password_configured: false,
            },
            password_update,
        ))
    }
}

/// 解析密码三态。
///
/// 兼容旧客户端只保留「省略字段」：
/// - 省略 `password_action` 且省略/`null` `password` → keep
/// - 省略 `password_action` 且 `password` 非空 → set
///
/// 空字符串不再等于 keep。显式 action 与 `password` 冲突或 `set` 缺值一律拒绝。
fn resolve_password_update(
    action: Option<SmtpPasswordAction>,
    password: Option<String>,
) -> Result<SmtpPasswordUpdate, SettingsValidationError> {
    match (action, password) {
        (Some(SmtpPasswordAction::Keep) | None, None) => Ok(SmtpPasswordUpdate::Keep),
        (Some(SmtpPasswordAction::Set), Some(value)) => require_set_password(value),
        (None, Some(value)) if !value.is_empty() => require_set_password(value),
        (Some(SmtpPasswordAction::Clear), None) => Ok(SmtpPasswordUpdate::Clear),
        (Some(SmtpPasswordAction::Set), None) => Err(SettingsValidationError::SmtpPasswordRequired),
        (Some(SmtpPasswordAction::Keep | SmtpPasswordAction::Clear), Some(_)) | (None, Some(_)) => {
            Err(SettingsValidationError::SmtpPasswordConflict)
        }
    }
}

fn require_set_password(value: String) -> Result<SmtpPasswordUpdate, SettingsValidationError> {
    if value.is_empty() || value.chars().count() > MAX_SMTP_PASSWORD_LENGTH {
        return Err(SettingsValidationError::InvalidSmtpPassword);
    }
    Ok(SmtpPasswordUpdate::Set(value))
}

#[cfg(test)]
#[path = "smtp_tests.rs"]
mod tests;
