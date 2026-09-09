use crate::{
    sqlx::PgPool,
    users::domain::{UserId, UserStatus},
};
use serde_json::Value;
use time::OffsetDateTime;

use super::claims::ExternalUser;

/// subject_hint 的脱敏摘要：首尾各保留少量字符，中间以星号遮蔽。
/// 绝不存 raw subject——它对 IdP 是账号主键，对旁观者是可关联的标识。
pub fn subject_hint(subject: &str) -> String {
    let chars: Vec<char> = subject.chars().collect();
    let keep = 2usize;
    if chars.len() <= keep * 2 {
        // 太短时全遮：保留任何字符都可能直接暴露短标识。
        return "*".repeat(chars.len().max(1));
    }
    let mut hint = String::with_capacity(chars.len());
    hint.extend(chars[..keep].iter());
    for _ in keep..chars.len() - keep {
        hint.push('*');
    }
    hint.extend(chars[chars.len() - keep..].iter());
    hint
}

#[derive(Debug, Clone)]
pub struct LinkedExternalIdentity {
    pub provider_slug: String,
    pub provider_name: String,
    pub subject: String,
    pub email: String,
    pub created_at: OffsetDateTime,
    pub account_name: Option<String>,
    pub avatar_url: Option<String>,
    pub provider_icon: Option<String>,
    pub subject_hint: Option<String>,
    pub account_status: Option<String>,
    pub last_synced_at: Option<OffsetDateTime>,
    pub sync_status: Option<String>,
    pub sync_error: Option<String>,
    pub extensions: Value,
    /// 生效套餐的到期时间（NULL = 永久或无套餐），供服务层组装订阅扩展。
    pub plan_expires_at: Option<OffsetDateTime>,
}

pub async fn list_identities(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Vec<LinkedExternalIdentity>, crate::sqlx::Error> {
    crate::sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            OffsetDateTime,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<OffsetDateTime>,
            Option<String>,
            Option<String>,
            Value,
            Option<OffsetDateTime>,
        ),
    >(
        "SELECT p.slug, p.name, i.subject, i.email, i.created_at,
                i.account_name, i.avatar_url, i.provider_icon, i.subject_hint,
                i.account_status, i.last_synced_at, i.sync_status, i.sync_error,
                i.extensions, u.plan_expires_at
         FROM oauth_external_identities i
         JOIN oauth_providers p ON p.id = i.provider_id
         JOIN users u ON u.id = i.user_id
         WHERE i.user_id = $1 ORDER BY i.created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(
                    provider_slug,
                    provider_name,
                    subject,
                    email,
                    created_at,
                    account_name,
                    avatar_url,
                    provider_icon,
                    subject_hint,
                    account_status,
                    last_synced_at,
                    sync_status,
                    sync_error,
                    extensions,
                    plan_expires_at,
                )| {
                    LinkedExternalIdentity {
                        provider_slug,
                        provider_name,
                        subject,
                        email,
                        created_at,
                        account_name,
                        avatar_url,
                        provider_icon,
                        subject_hint,
                        account_status,
                        last_synced_at,
                        sync_status,
                        sync_error,
                        extensions,
                        plan_expires_at,
                    }
                },
            )
            .collect()
    })
}

pub async fn bind_identity(
    pool: &PgPool,
    user_id: UserId,
    expected_session_epoch: i64,
    provider_id: i64,
    external: &ExternalUser,
) -> Result<(), BindIdentityError> {
    let mut transaction = pool.begin().await?;
    let user_state: Option<(i64, String)> =
        crate::sqlx::query_as("SELECT session_epoch, status FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?;
    if !user_state.is_some_and(|(epoch, ref status)| {
        epoch == expected_session_epoch && UserStatus::parse(status) == Some(UserStatus::Active)
    }) {
        transaction.rollback().await?;
        return Err(BindIdentityError::AuthenticationChanged);
    }
    let subject_owner: Option<UserId> = crate::sqlx::query_scalar(
        "SELECT user_id FROM oauth_external_identities WHERE provider_id = $1 AND subject = $2 FOR UPDATE",
    )
    .bind(provider_id)
    .bind(&external.subject)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(owner) = subject_owner {
        transaction.rollback().await?;
        return Err(if owner == user_id {
            BindIdentityError::AlreadyOwned
        } else {
            BindIdentityError::OwnedByAnotherUser
        });
    }
    let provider_slot: Option<UserId> = crate::sqlx::query_scalar(
        "SELECT user_id FROM oauth_external_identities WHERE provider_id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(provider_id)
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if provider_slot.is_some() {
        transaction.rollback().await?;
        return Err(BindIdentityError::AlreadyOwned);
    }
    let inserted = crate::sqlx::query(
        "INSERT INTO oauth_external_identities
         (provider_id, user_id, subject, email, created_at, updated_at,
          account_name, avatar_url, subject_hint, last_synced_at, sync_status, extensions)
         VALUES ($1, $2, $3, $4, NOW(), NOW(), $5, $6, $7, NOW(), 'success', '[]'::jsonb)
         ON CONFLICT DO NOTHING",
    )
    .bind(provider_id)
    .bind(user_id)
    .bind(&external.subject)
    .bind(external.email.display())
    .bind(external.account_name.as_deref())
    .bind(external.avatar_url.as_deref())
    .bind(subject_hint(&external.subject))
    .execute(&mut *transaction)
    .await?;
    if inserted.rows_affected() == 0 {
        let owner: Option<UserId> = crate::sqlx::query_scalar(
            "SELECT user_id FROM oauth_external_identities WHERE provider_id = $1 AND subject = $2",
        )
        .bind(provider_id)
        .bind(&external.subject)
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.rollback().await?;
        return Err(match owner {
            Some(owner) if owner != user_id => BindIdentityError::OwnedByAnotherUser,
            _ => BindIdentityError::AlreadyOwned,
        });
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn unlink_identity(
    pool: &PgPool,
    user_id: UserId,
    expected_session_epoch: i64,
    provider_slug: &str,
) -> Result<UnlinkIdentityOutcome, crate::sqlx::Error> {
    // Unlink changes a recovery/login route but does not revoke the current authenticated
    // session. The epoch check prevents a password reauthentication raced by credential
    // revocation from authorizing the delete; successful unlink intentionally leaves epoch unchanged.
    let mut transaction = pool.begin().await?;
    let credentials: Option<(bool, i64)> = crate::sqlx::query_as(
        "SELECT password_login_enabled, session_epoch FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((password_login_enabled, session_epoch)) = credentials else {
        transaction.rollback().await?;
        return Ok(UnlinkIdentityOutcome::Missing);
    };
    if session_epoch != expected_session_epoch {
        transaction.rollback().await?;
        return Ok(UnlinkIdentityOutcome::AuthenticationChanged);
    }
    let identity: Option<(i64,)> = crate::sqlx::query_as(
        "SELECT i.id FROM oauth_external_identities i JOIN oauth_providers p ON p.id = i.provider_id
         WHERE i.user_id = $1 AND p.slug = $2 FOR UPDATE OF i",
    )
    .bind(user_id)
    .bind(provider_slug)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((identity_id,)) = identity else {
        transaction.rollback().await?;
        return Ok(UnlinkIdentityOutcome::Missing);
    };
    // Lock the usable Passkey rows before deciding whether this identity is the sole login
    // credential. A concurrent Passkey removal must serialize with this decision.
    let passkey_rows: Vec<(i64,)> =
        crate::sqlx::query_as("SELECT id FROM user_passkeys WHERE user_id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_all(&mut *transaction)
            .await?;
    if !password_login_enabled && passkey_rows.is_empty() {
        transaction.rollback().await?;
        return Ok(UnlinkIdentityOutcome::LastCredential);
    }
    crate::sqlx::query("DELETE FROM oauth_external_identities WHERE id = $1")
        .bind(identity_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(UnlinkIdentityOutcome::Removed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlinkIdentityOutcome {
    Removed,
    Missing,
    LastCredential,
    AuthenticationChanged,
}

#[derive(Debug, thiserror::Error)]
pub enum BindIdentityError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("external identity is already linked to this user")]
    AlreadyOwned,
    #[error("external identity is owned by another user")]
    OwnedByAnotherUser,
    #[error("external identity binding session is no longer current")]
    AuthenticationChanged,
}

#[cfg(test)]
mod tests {
    use super::subject_hint;

    #[test]
    fn long_subject_keeps_head_and_tail() {
        assert_eq!(subject_hint("gh-subject-42"), "gh*********42");
    }

    #[test]
    fn short_subject_is_fully_masked() {
        assert_eq!(subject_hint("abc"), "***");
        assert_eq!(subject_hint("abcd"), "****");
    }

    #[test]
    fn empty_subject_still_produces_a_hint() {
        assert_eq!(subject_hint(""), "*");
    }
}
