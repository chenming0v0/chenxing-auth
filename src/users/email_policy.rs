use crate::settings::EmailPolicySetting;
use crate::sqlx::PgPool;

use super::service::UserServiceError;

pub(super) async fn ensure_email_policy_allows(
    pool: &PgPool,
    email: &str,
) -> Result<(), UserServiceError> {
    let raw = crate::sqlx::query_as::<_, (Option<String>,)>(
        "SELECT setting_value FROM app_settings WHERE setting_key = 'email_policy'",
    )
    .fetch_optional(pool)
    .await?;
    let policy = match raw.and_then(|(value,)| value) {
        Some(value) if !value.trim().is_empty() => {
            serde_json::from_str::<EmailPolicySetting>(&value).unwrap_or_default()
        }
        _ => EmailPolicySetting::default(),
    };
    if policy.allows_email(email) {
        Ok(())
    } else {
        Err(UserServiceError::EmailDomainNotAllowed)
    }
}
