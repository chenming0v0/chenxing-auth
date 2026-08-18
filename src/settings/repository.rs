use super::{
    EMAIL_POLICY_KEY, PASSKEY_KEY, REGISTRATION_EMAIL_FROM_KEY, REGISTRATION_SETTING_KEY,
    SECURITY_LIMITS_KEY, SESSION_LIFETIME_KEY, SMTP_KEY, SecurityLimitsSetting,
    SessionLifetimeSetting,
    domain::{EmailPolicySetting, PasskeySetting, RegistrationSetting},
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

/// Materialize and lock the mirrored email-setting rows in one stable order.
///
/// Both multi-key writers call this immediately after opening their transaction.
/// The returned SMTP value comes from the locked snapshot, so password retention
/// and sender mirroring never depend on a second unlocked read (#482).
pub(crate) async fn lock_registration_email_and_smtp(
    connection: &mut crate::sqlx::PgConnection,
) -> Result<Option<StoredSmtpSetting>, crate::sqlx::Error> {
    let mut keys = [REGISTRATION_EMAIL_FROM_KEY, SMTP_KEY];
    keys.sort_unstable();
    for key in &keys {
        crate::sqlx::query(
            "INSERT INTO app_settings (setting_key, setting_value, updated_at)
             VALUES ($1, NULL, NOW())
             ON CONFLICT (setting_key) DO NOTHING",
        )
        .bind(*key)
        .execute(&mut *connection)
        .await?;
    }

    let rows = crate::sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT setting_key, setting_value
         FROM app_settings
         WHERE setting_key IN ($1, $2)
         ORDER BY setting_key
         FOR UPDATE",
    )
    .bind(keys[0])
    .bind(keys[1])
    .fetch_all(&mut *connection)
    .await?;
    if rows.len() != keys.len() {
        return Err(crate::sqlx::Error::RowNotFound);
    }
    let smtp_raw = rows
        .into_iter()
        .find(|(key, _)| key == SMTP_KEY)
        .ok_or(crate::sqlx::Error::RowNotFound)?
        .1;
    decode_smtp(smtp_raw)
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

pub async fn set_registration<'e, E>(
    executor: E,
    value: &RegistrationSetting,
) -> Result<(), crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    let raw = serde_json::to_string(value).map_err(json_error)?;
    set_text(executor, REGISTRATION_SETTING_KEY, Some(&raw)).await
}

/// Serialize passkey policy writes with authentication decisions that read the
/// policy inside a session/factor transaction.
///
/// A setting row lock is insufficient when the row does not exist yet, so both
/// sides use this stable advisory key. This keeps the default-enabled case
/// atomic with the first persisted setting write as well.
pub(crate) async fn lock_passkey_policy(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
) -> Result<(), crate::sqlx::Error> {
    crate::db::advisory_lock::lock_business(
        transaction,
        crate::db::advisory_lock::BusinessLock::PasskeyPolicy,
    )
    .await
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

pub async fn set_session_lifetime<'e, E>(
    executor: E,
    value: &SessionLifetimeSetting,
) -> Result<(), crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    let raw = serde_json::to_string(value).map_err(json_error)?;
    set_text(executor, SESSION_LIFETIME_KEY, Some(&raw)).await
}

pub(crate) async fn get_smtp<'e, E>(
    executor: E,
) -> Result<Option<StoredSmtpSetting>, crate::sqlx::Error>
where
    E: crate::sqlx::Executor<'e, Database = crate::sqlx::Postgres>,
{
    decode_smtp(get_text(executor, SMTP_KEY).await?)
}

fn decode_smtp(value: Option<String>) -> Result<Option<StoredSmtpSetting>, crate::sqlx::Error> {
    match value {
        Some(raw) if !raw.trim().is_empty() => {
            serde_json::from_str(&raw).map(Some).map_err(json_error)
        }
        _ => Ok(None),
    }
}

/// Whether the SMTP setting contains a non-empty encrypted password.
///
/// Parse through the same typed representation as normal reads. Malformed persisted JSON is
/// an error, not evidence that startup may safely generate a replacement encryption key.
pub(crate) async fn has_smtp_password_ciphertext(
    pool: &crate::sqlx::PgPool,
) -> Result<bool, crate::sqlx::Error> {
    Ok(get_smtp(pool).await?.is_some_and(|setting| {
        setting
            .password_ciphertext
            .as_deref()
            .is_some_and(|ciphertext| !ciphertext.is_empty())
    }))
}

pub(crate) async fn lock_smtp_for_secret_migration(
    connection: &mut crate::sqlx::PgConnection,
) -> Result<Option<StoredSmtpSetting>, crate::sqlx::Error> {
    let value = crate::sqlx::query_scalar::<_, Option<String>>(
        "SELECT setting_value
         FROM app_settings
         WHERE setting_key = $1
         FOR UPDATE",
    )
    .bind(SMTP_KEY)
    .fetch_optional(&mut *connection)
    .await?
    .flatten();
    decode_smtp(value)
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
