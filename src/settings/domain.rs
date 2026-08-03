use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::users::domain::is_valid_email;

const MAX_RP_NAME_LENGTH: usize = 128;
const MAX_RP_ID_LENGTH: usize = 253;
const MAX_ORIGINS: usize = 32;
const MAX_DOMAINS: usize = 128;
const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_SMTP_HOST_LENGTH: usize = 253;
const MAX_SMTP_USERNAME_LENGTH: usize = 256;
const MAX_SMTP_FROM_LENGTH: usize = 320;
const MAX_SMTP_PASSWORD_LENGTH: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyUserVerification {
    #[default]
    Preferred,
    Required,
    Discouraged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyAuthenticatorAttachment {
    #[default]
    Any,
    Platform,
    CrossPlatform,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeySetting {
    pub enabled: bool,
    pub rp_name: String,
    pub rp_id: String,
    pub user_verification: PasskeyUserVerification,
    pub authenticator_attachment: PasskeyAuthenticatorAttachment,
    pub allow_insecure_origin: bool,
    pub allowed_origins: Vec<String>,
}

impl Default for PasskeySetting {
    fn default() -> Self {
        Self {
            enabled: true,
            rp_name: "辰星认证中枢".to_owned(),
            rp_id: String::new(),
            user_verification: PasskeyUserVerification::Preferred,
            authenticator_attachment: PasskeyAuthenticatorAttachment::Any,
            allow_insecure_origin: false,
            allowed_origins: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailPolicySetting {
    pub whitelist_enabled: bool,
    pub alias_restriction_enabled: bool,
    pub allowed_domains: Vec<String>,
}

impl Default for EmailPolicySetting {
    fn default() -> Self {
        Self {
            whitelist_enabled: false,
            alias_restriction_enabled: false,
            allowed_domains: Vec::new(),
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

#[derive(Debug, Clone, Deserialize)]
pub struct SmtpSettingUpdate {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from_address: String,
    pub ssl_enabled: bool,
    pub force_auth_login: bool,
    /// Write-only. Omit or null to keep the existing password.
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SettingsValidationError {
    #[error("passkey relying party name is invalid")]
    InvalidPasskeyRpName,
    #[error("passkey relying party id is invalid")]
    InvalidPasskeyRpId,
    #[error("passkey origin is invalid")]
    InvalidPasskeyOrigin,
    #[error("email domain is invalid")]
    InvalidEmailDomain,
    #[error("smtp host is invalid")]
    InvalidSmtpHost,
    #[error("smtp port is invalid")]
    InvalidSmtpPort,
    #[error("smtp username is invalid")]
    InvalidSmtpUsername,
    #[error("smtp sender address is invalid")]
    InvalidSmtpFrom,
    #[error("smtp password is invalid")]
    InvalidSmtpPassword,
}

impl PasskeySetting {
    pub fn with_runtime_defaults(mut self, rp_id: &str, origin: &str) -> Self {
        if self.rp_id.trim().is_empty() {
            self.rp_id = rp_id.trim().to_owned();
        }
        if self.allowed_origins.is_empty() {
            let origin = origin.trim();
            if !origin.is_empty() {
                self.allowed_origins.push(origin.to_owned());
            }
        }
        if self.rp_name.trim().is_empty() {
            self.rp_name = "辰星认证中枢".to_owned();
        }
        self
    }

    pub fn validate(self) -> Result<Self, SettingsValidationError> {
        let rp_name = self.rp_name.trim().to_owned();
        if rp_name.is_empty() || rp_name.chars().count() > MAX_RP_NAME_LENGTH {
            return Err(SettingsValidationError::InvalidPasskeyRpName);
        }
        let rp_id = self.rp_id.trim().to_ascii_lowercase();
        if rp_id.is_empty()
            || rp_id.chars().count() > MAX_RP_ID_LENGTH
            || rp_id.starts_with('.')
            || rp_id.ends_with('.')
            || rp_id.contains("..")
            || !rp_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '-' || character == '.'
            })
        {
            return Err(SettingsValidationError::InvalidPasskeyRpId);
        }
        let allowed_origins = normalize_origins(self.allowed_origins, self.allow_insecure_origin)?;
        if allowed_origins.is_empty() {
            return Err(SettingsValidationError::InvalidPasskeyOrigin);
        }
        for origin in &allowed_origins {
            let url =
                Url::parse(origin).map_err(|_| SettingsValidationError::InvalidPasskeyOrigin)?;
            let host = url
                .host_str()
                .ok_or(SettingsValidationError::InvalidPasskeyOrigin)?
                .to_ascii_lowercase();
            if !(host == rp_id || host.ends_with(&format!(".{rp_id}"))) {
                return Err(SettingsValidationError::InvalidPasskeyOrigin);
            }
        }
        Ok(Self {
            enabled: self.enabled,
            rp_name,
            rp_id,
            user_verification: self.user_verification,
            authenticator_attachment: self.authenticator_attachment,
            allow_insecure_origin: self.allow_insecure_origin,
            allowed_origins,
        })
    }
}

impl EmailPolicySetting {
    pub fn validate(self) -> Result<Self, SettingsValidationError> {
        let mut allowed_domains = Vec::new();
        for domain in self.allowed_domains {
            let domain = domain.trim().to_ascii_lowercase();
            if domain.is_empty() {
                continue;
            }
            if domain.chars().count() > MAX_DOMAIN_LENGTH
                || domain.starts_with('.')
                || domain.ends_with('.')
                || domain.contains("..")
                || domain.contains('@')
                || !domain.contains('.')
                || !domain.chars().all(|character| {
                    character.is_ascii_alphanumeric() || character == '-' || character == '.'
                })
            {
                return Err(SettingsValidationError::InvalidEmailDomain);
            }
            if !allowed_domains.contains(&domain) {
                allowed_domains.push(domain);
            }
            if allowed_domains.len() > MAX_DOMAINS {
                return Err(SettingsValidationError::InvalidEmailDomain);
            }
        }
        if self.whitelist_enabled && allowed_domains.is_empty() {
            return Err(SettingsValidationError::InvalidEmailDomain);
        }
        Ok(Self {
            whitelist_enabled: self.whitelist_enabled,
            alias_restriction_enabled: self.alias_restriction_enabled,
            allowed_domains,
        })
    }

    pub fn allows_email(&self, email: &str) -> bool {
        let email = email.trim().to_ascii_lowercase();
        let Some((local, domain)) = email.split_once('@') else {
            return false;
        };
        if self.alias_restriction_enabled && local.contains('+') {
            return false;
        }
        if !self.whitelist_enabled {
            return true;
        }
        self.allowed_domains.iter().any(|allowed| domain == allowed)
    }
}

impl SmtpSettingUpdate {
    pub fn validate(self) -> Result<(SmtpSetting, Option<String>), SettingsValidationError> {
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
        if from_address.chars().count() > MAX_SMTP_FROM_LENGTH {
            return Err(SettingsValidationError::InvalidSmtpFrom);
        }
        if !from_address.is_empty() && !is_valid_sender(&from_address) {
            return Err(SettingsValidationError::InvalidSmtpFrom);
        }
        let password = match self.password {
            Some(value) if value.is_empty() => None,
            Some(value) if value.chars().count() > MAX_SMTP_PASSWORD_LENGTH => {
                return Err(SettingsValidationError::InvalidSmtpPassword);
            }
            Some(value) => Some(value),
            None => None,
        };
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
            password,
        ))
    }
}

fn normalize_origins(
    origins: Vec<String>,
    allow_insecure_origin: bool,
) -> Result<Vec<String>, SettingsValidationError> {
    let mut normalized = Vec::new();
    for origin in origins {
        for part in origin.split([',', ' ', '\n', '\r', '\t']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let url =
                Url::parse(part).map_err(|_| SettingsValidationError::InvalidPasskeyOrigin)?;
            if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
                return Err(SettingsValidationError::InvalidPasskeyOrigin);
            }
            if !url.username().is_empty() || url.password().is_some() {
                return Err(SettingsValidationError::InvalidPasskeyOrigin);
            }
            let scheme_ok = match url.scheme() {
                "https" => true,
                "http" => allow_insecure_origin || is_loopback_host(&url),
                _ => false,
            };
            if !scheme_ok || url.host_str().is_none() {
                return Err(SettingsValidationError::InvalidPasskeyOrigin);
            }
            let value = origin_key(&url)?;
            if !normalized.contains(&value) {
                normalized.push(value);
            }
            if normalized.len() > MAX_ORIGINS {
                return Err(SettingsValidationError::InvalidPasskeyOrigin);
            }
        }
    }
    Ok(normalized)
}

fn origin_key(url: &Url) -> Result<String, SettingsValidationError> {
    let host = url
        .host_str()
        .ok_or(SettingsValidationError::InvalidPasskeyOrigin)?
        .to_ascii_lowercase();
    Ok(match url.port_or_known_default() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    })
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn is_valid_sender(value: &str) -> bool {
    if is_valid_email(value) {
        return true;
    }
    let Some(start) = value.find('<') else {
        return false;
    };
    let Some(end) = value[start + 1..].find('>') else {
        return false;
    };
    let email = &value[start + 1..start + 1 + end];
    is_valid_email(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_passkey_and_email_policy() {
        let passkey = PasskeySetting {
            enabled: true,
            rp_name: "辰星认证中枢".to_owned(),
            rp_id: "auth.clya.top".to_owned(),
            user_verification: PasskeyUserVerification::Preferred,
            authenticator_attachment: PasskeyAuthenticatorAttachment::Any,
            allow_insecure_origin: false,
            allowed_origins: vec!["https://auth.clya.top".to_owned()],
        }
        .validate()
        .expect("passkey");
        assert_eq!(
            passkey.allowed_origins,
            vec!["https://auth.clya.top:443".to_owned()]
        );

        let policy = EmailPolicySetting {
            whitelist_enabled: true,
            alias_restriction_enabled: true,
            allowed_domains: vec!["Gmail.COM".to_owned(), "gmail.com".to_owned()],
        }
        .validate()
        .expect("policy");
        assert_eq!(policy.allowed_domains, vec!["gmail.com".to_owned()]);
        assert!(policy.allows_email("user@gmail.com"));
        assert!(!policy.allows_email("user+tag@gmail.com"));
        assert!(!policy.allows_email("user@tempmail.com"));
    }
}
