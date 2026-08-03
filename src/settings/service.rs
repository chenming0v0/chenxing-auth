use super::{
    domain::{
        EmailPolicySetting, PasskeySetting, SettingsValidationError, SmtpSetting,
        SmtpSettingUpdate, StoredSmtpSetting,
    },
    repository,
};
use crate::{
    config::AuthEncryptionKey,
    oauth::providers::secrets::{SecretError, SecretManager},
};
use thiserror::Error;

#[derive(Clone)]
pub struct SettingsService {
    pool: crate::sqlx::PgPool,
    secrets: SecretManager,
    default_passkey: PasskeySetting,
}

#[derive(Debug, Error)]
pub enum SettingsServiceError {
    #[error("registration sender email is invalid")]
    InvalidEmail,
    #[error("setting validation failed: {0}")]
    Validation(#[from] SettingsValidationError),
    #[error("secret operation failed: {0}")]
    Secret(#[from] SecretError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

impl SettingsService {
    pub fn new(
        pool: crate::sqlx::PgPool,
        secrets: SecretManager,
        default_rp_id: &str,
        default_origin: &str,
    ) -> Self {
        Self {
            pool,
            secrets,
            default_passkey: PasskeySetting::default()
                .with_runtime_defaults(default_rp_id, default_origin),
        }
    }

    pub fn from_encryption_key(
        pool: crate::sqlx::PgPool,
        encryption_key: &AuthEncryptionKey,
        default_rp_id: &str,
        default_origin: &str,
    ) -> Self {
        Self::new(
            pool,
            SecretManager::from_key(*encryption_key.as_bytes()),
            default_rp_id,
            default_origin,
        )
    }

    pub async fn registration_email_from(&self) -> Result<Option<String>, SettingsServiceError> {
        let smtp = self.smtp().await?;
        if !smtp.from_address.is_empty()
            && let Some(email) = extract_email(&smtp.from_address)
        {
            return Ok(Some(email));
        }
        Ok(repository::get_registration_email_from(&self.pool).await?)
    }

    pub async fn set_registration_email_from(
        &self,
        value: Option<String>,
    ) -> Result<Option<String>, SettingsServiceError> {
        let value = normalize_email(value)?;
        repository::set_registration_email_from(&self.pool, value.as_deref()).await?;
        if let Some(email) = value.as_deref() {
            let mut smtp =
                repository::get_smtp(&self.pool)
                    .await?
                    .unwrap_or_else(|| StoredSmtpSetting {
                        host: String::new(),
                        port: 587,
                        username: String::new(),
                        from_address: String::new(),
                        ssl_enabled: true,
                        force_auth_login: false,
                        password_ciphertext: None,
                    });
            if smtp.from_address.trim().is_empty() {
                smtp.from_address = email.to_owned();
                repository::set_smtp(&self.pool, &smtp).await?;
            }
        }
        Ok(value)
    }

    pub async fn passkey(&self) -> Result<PasskeySetting, SettingsServiceError> {
        Ok(repository::get_passkey(&self.pool)
            .await?
            .unwrap_or_else(|| self.default_passkey.clone())
            .with_runtime_defaults(
                &self.default_passkey.rp_id,
                self.default_passkey
                    .allowed_origins
                    .first()
                    .map(String::as_str)
                    .unwrap_or_default(),
            ))
    }

    pub async fn set_passkey(
        &self,
        value: PasskeySetting,
    ) -> Result<PasskeySetting, SettingsServiceError> {
        let value = value.validate()?;
        repository::set_passkey(&self.pool, &value).await?;
        Ok(value)
    }

    pub async fn email_policy(&self) -> Result<EmailPolicySetting, SettingsServiceError> {
        Ok(repository::get_email_policy(&self.pool)
            .await?
            .unwrap_or_default())
    }

    pub async fn set_email_policy(
        &self,
        value: EmailPolicySetting,
    ) -> Result<EmailPolicySetting, SettingsServiceError> {
        let value = value.validate()?;
        repository::set_email_policy(&self.pool, &value).await?;
        Ok(value)
    }

    pub async fn smtp(&self) -> Result<SmtpSetting, SettingsServiceError> {
        Ok(match repository::get_smtp(&self.pool).await? {
            Some(stored) => SmtpSetting {
                host: stored.host,
                port: stored.port,
                username: stored.username,
                from_address: stored.from_address,
                ssl_enabled: stored.ssl_enabled,
                force_auth_login: stored.force_auth_login,
                password_configured: stored
                    .password_ciphertext
                    .as_ref()
                    .is_some_and(|value| !value.is_empty()),
            },
            None => {
                let mut setting = SmtpSetting::default();
                if let Some(from) = repository::get_registration_email_from(&self.pool).await? {
                    setting.from_address = from;
                }
                setting
            }
        })
    }

    pub async fn set_smtp(
        &self,
        update: SmtpSettingUpdate,
    ) -> Result<SmtpSetting, SettingsServiceError> {
        let (mut setting, password) = update.validate()?;
        let existing = repository::get_smtp(&self.pool).await?;
        let password_ciphertext = match password {
            Some(password) => Some(SecretManager::encode(&self.secrets.encrypt(&password)?)),
            None => existing
                .as_ref()
                .and_then(|value| value.password_ciphertext.clone()),
        };
        setting.password_configured = password_ciphertext
            .as_ref()
            .is_some_and(|value| !value.is_empty());
        let stored = StoredSmtpSetting {
            host: setting.host.clone(),
            port: setting.port,
            username: setting.username.clone(),
            from_address: setting.from_address.clone(),
            ssl_enabled: setting.ssl_enabled,
            force_auth_login: setting.force_auth_login,
            password_ciphertext,
        };
        repository::set_smtp(&self.pool, &stored).await?;
        if let Some(email) = extract_email(&setting.from_address) {
            repository::set_registration_email_from(&self.pool, Some(&email)).await?;
        }
        Ok(setting)
    }
}

fn normalize_email(value: Option<String>) -> Result<Option<String>, SettingsServiceError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Ok(None);
    }
    if !crate::users::domain::is_valid_email(&value) {
        return Err(SettingsServiceError::InvalidEmail);
    }
    Ok(Some(value))
}

fn extract_email(value: &str) -> Option<String> {
    let value = value.trim();
    if crate::users::domain::is_valid_email(value) {
        return Some(value.to_ascii_lowercase());
    }
    let start = value.find('<')?;
    let end = value[start + 1..].find('>')?;
    let email = value[start + 1..start + 1 + end]
        .trim()
        .to_ascii_lowercase();
    crate::users::domain::is_valid_email(&email).then_some(email)
}

#[cfg(test)]
mod tests {
    use super::normalize_email;

    #[test]
    fn normalizes_and_clears_registration_sender_email() {
        assert_eq!(
            normalize_email(Some("  Sender@Example.COM ".to_owned())).unwrap(),
            Some("sender@example.com".to_owned())
        );
        assert_eq!(normalize_email(Some("  ".to_owned())).unwrap(), None);
        assert!(normalize_email(Some("invalid".to_owned())).is_err());
    }
}
