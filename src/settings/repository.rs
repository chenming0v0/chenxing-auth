use super::{
    EMAIL_POLICY_KEY, PASSKEY_KEY, REGISTRATION_EMAIL_FROM_KEY, SMTP_KEY,
    domain::{EmailPolicySetting, PasskeySetting, StoredSmtpSetting},
};
use crate::sqlx::PgPool;

pub async fn get_text(pool: &PgPool, key: &str) -> Result<Option<String>, crate::sqlx::Error> {
    let row = crate::sqlx::query_as::<_, (Option<String>,)>(
        "SELECT setting_value FROM app_settings WHERE setting_key = $1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(value,)| value))
}

pub async fn set_text(
    pool: &PgPool,
    key: &str,
    value: Option<&str>,
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query(
        "INSERT INTO app_settings (setting_key, setting_value, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (setting_key) DO UPDATE
         SET setting_value = EXCLUDED.setting_value, updated_at = EXCLUDED.updated_at",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_registration_email_from(
    pool: &PgPool,
) -> Result<Option<String>, crate::sqlx::Error> {
    get_text(pool, REGISTRATION_EMAIL_FROM_KEY).await
}

pub async fn set_registration_email_from(
    pool: &PgPool,
    value: Option<&str>,
) -> Result<(), crate::sqlx::Error> {
    set_text(pool, REGISTRATION_EMAIL_FROM_KEY, value).await
}

pub async fn get_passkey(pool: &PgPool) -> Result<Option<PasskeySetting>, crate::sqlx::Error> {
    match get_text(pool, PASSKEY_KEY).await? {
        Some(raw) if !raw.trim().is_empty() => {
            serde_json::from_str(&raw).map(Some).map_err(json_error)
        }
        _ => Ok(None),
    }
}

pub async fn set_passkey(pool: &PgPool, value: &PasskeySetting) -> Result<(), crate::sqlx::Error> {
    let raw = serde_json::to_string(value).map_err(json_error)?;
    set_text(pool, PASSKEY_KEY, Some(&raw)).await
}

pub async fn get_email_policy(
    pool: &PgPool,
) -> Result<Option<EmailPolicySetting>, crate::sqlx::Error> {
    match get_text(pool, EMAIL_POLICY_KEY).await? {
        Some(raw) if !raw.trim().is_empty() => {
            serde_json::from_str(&raw).map(Some).map_err(json_error)
        }
        _ => Ok(None),
    }
}

pub async fn set_email_policy(
    pool: &PgPool,
    value: &EmailPolicySetting,
) -> Result<(), crate::sqlx::Error> {
    let raw = serde_json::to_string(value).map_err(json_error)?;
    set_text(pool, EMAIL_POLICY_KEY, Some(&raw)).await
}

pub(crate) async fn get_smtp(
    pool: &PgPool,
) -> Result<Option<StoredSmtpSetting>, crate::sqlx::Error> {
    match get_text(pool, SMTP_KEY).await? {
        Some(raw) if !raw.trim().is_empty() => {
            serde_json::from_str(&raw).map(Some).map_err(json_error)
        }
        _ => Ok(None),
    }
}

pub(crate) async fn set_smtp(
    pool: &PgPool,
    value: &StoredSmtpSetting,
) -> Result<(), crate::sqlx::Error> {
    let raw = serde_json::to_string(value).map_err(json_error)?;
    set_text(pool, SMTP_KEY, Some(&raw)).await
}

fn json_error(error: serde_json::Error) -> crate::sqlx::Error {
    crate::sqlx::Error::Decode(Box::new(error))
}
