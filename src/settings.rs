use thiserror::Error;

pub const REGISTRATION_EMAIL_FROM_KEY: &str = "registration_email_from";

#[derive(Clone)]
pub struct SettingsService {
    pool: crate::sqlx::PgPool,
}

#[derive(Debug, Error)]
pub enum SettingsServiceError {
    #[error("registration sender email is invalid")]
    InvalidEmail,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

impl SettingsService {
    pub fn new(pool: crate::sqlx::PgPool) -> Self {
        Self { pool }
    }

    pub async fn registration_email_from(&self) -> Result<Option<String>, SettingsServiceError> {
        let row = crate::sqlx::query_as::<_, (Option<String>,)>(
            "SELECT setting_value FROM app_settings WHERE setting_key = $1",
        )
        .bind(REGISTRATION_EMAIL_FROM_KEY)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(value,)| value))
    }

    pub async fn set_registration_email_from(
        &self,
        value: Option<String>,
    ) -> Result<Option<String>, SettingsServiceError> {
        let value = normalize_email(value)?;
        crate::sqlx::query(
            "INSERT INTO app_settings (setting_key, setting_value, updated_at)
             VALUES ($1, $2, NOW())
             ON CONFLICT (setting_key) DO UPDATE
             SET setting_value = EXCLUDED.setting_value, updated_at = EXCLUDED.updated_at",
        )
        .bind(REGISTRATION_EMAIL_FROM_KEY)
        .bind(&value)
        .execute(&self.pool)
        .await?;
        Ok(value)
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
