use crate::{
    sqlx::PgPool,
    users::domain::{UserId, UserStatus},
};
use time::OffsetDateTime;

use super::claims::ExternalUser;

#[derive(Debug, Clone)]
pub struct LinkedExternalIdentity {
    pub provider_slug: String,
    pub provider_name: String,
    pub subject: String,
    pub email: String,
    pub created_at: OffsetDateTime,
}

pub async fn list_identities(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Vec<LinkedExternalIdentity>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (String, String, String, String, OffsetDateTime)>(
        "SELECT p.slug, p.name, i.subject, i.email, i.created_at
         FROM oauth_external_identities i
         JOIN oauth_providers p ON p.id = i.provider_id
         WHERE i.user_id = $1 ORDER BY i.created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(provider_slug, provider_name, subject, email, created_at)| {
                    LinkedExternalIdentity {
                        provider_slug,
                        provider_name,
                        subject,
                        email,
                        created_at,
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
        "INSERT INTO oauth_external_identities (provider_id, user_id, subject, email, created_at, updated_at)
         VALUES ($1, $2, $3, $4, NOW(), NOW()) ON CONFLICT DO NOTHING",
    )
    .bind(provider_id)
    .bind(user_id)
    .bind(&external.subject)
    .bind(external.email.display())
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
