use super::{
    EMAIL_POLICY_KEY, PASSKEY_KEY, REGISTRATION_EMAIL_FROM_KEY, SECURITY_LIMITS_KEY, SMTP_KEY,
    SecurityLimitsSetting,
    domain::{EmailPolicySetting, PasskeySetting},
    smtp::StoredSmtpSetting,
};

/// 所有读写都接受任意 PostgreSQL 执行器：单键路径直接传 `&PgPool`，
/// 多键写入由 service 层开事务后传 `&mut *transaction`，保证一组键要么全部
/// 落库、要么全部回滚（#322）。
pub async fn get_text<'e, E>(executor: E, key: &str) -> Result<Option<String>, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    let row = crate::sqlx::query_as::<_, (Option<String>,)>(
        "SELECT setting_value FROM app_settings WHERE setting_key = $1",
    )
    .bind(key)
    .fetch_optional(executor)
    .await?;
    Ok(row.and_then(|(value,)| value))
}

pub async fn set_text<'e, E>(
    executor: E,
    key: &str,
    value: Option<&str>,
) -> Result<(), crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    crate::sqlx::query(
        "INSERT INTO app_settings (setting_key, setting_value, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (setting_key) DO UPDATE
         SET setting_value = EXCLUDED.setting_value, updated_at = EXCLUDED.updated_at",
    )
    .bind(key)
    .bind(value)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get_registration_email_from<'e, E>(
    executor: E,
) -> Result<Option<String>, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    get_text(executor, REGISTRATION_EMAIL_FROM_KEY).await
}

pub async fn set_registration_email_from<'e, E>(
    executor: E,
    value: Option<&str>,
) -> Result<(), crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    set_text(executor, REGISTRATION_EMAIL_FROM_KEY, value).await
}

pub async fn set_passkey<'e, E>(
    executor: E,
    value: &PasskeySetting,
) -> Result<(), crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    let raw = serde_json::to_string(value).map_err(json_error)?;
    set_text(executor, PASSKEY_KEY, Some(&raw)).await
}

/// Serialize passkey policy writes with authentication decisions that read the
/// policy inside a session/factor transaction.
///
/// A setting row lock is insufficient when the row does not exist yet, so both
/// sides use this stable advisory key. This keeps the default-enabled case
/// atomic with the first persisted setting write as well.
pub(crate) async fn lock_passkey_policy<'e, E>(executor: E) -> Result<(), crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    crate::sqlx::query("SELECT pg_advisory_xact_lock(0, 7341931)")
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn set_email_policy<'e, E>(
    executor: E,
    value: &EmailPolicySetting,
) -> Result<(), crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    let raw = serde_json::to_string(value).map_err(json_error)?;
    set_text(executor, EMAIL_POLICY_KEY, Some(&raw)).await
}

pub async fn set_security_limits<'e, E>(
    executor: E,
    value: &SecurityLimitsSetting,
) -> Result<(), crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    let raw = serde_json::to_string(value).map_err(json_error)?;
    set_text(executor, SECURITY_LIMITS_KEY, Some(&raw)).await
}

pub(crate) async fn get_smtp<'e, E>(
    executor: E,
) -> Result<Option<StoredSmtpSetting>, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    match get_text(executor, SMTP_KEY).await? {
        Some(raw) if !raw.trim().is_empty() => {
            serde_json::from_str(&raw).map(Some).map_err(json_error)
        }
        _ => Ok(None),
    }
}

pub(crate) async fn set_smtp<'e, E>(
    executor: E,
    value: &StoredSmtpSetting,
) -> Result<(), crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    let raw = serde_json::to_string(value).map_err(json_error)?;
    set_text(executor, SMTP_KEY, Some(&raw)).await
}

fn json_error(error: serde_json::Error) -> crate::sqlx::Error {
    crate::sqlx::Error::Decode(Box::new(error))
}
