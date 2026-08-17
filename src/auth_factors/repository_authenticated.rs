use super::{issuer_generation_matches, lock_factor_account};
use crate::{sqlx::PgPool, users::domain::UserId};
use webauthn_rs::prelude::Passkey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedTotpPersistenceResult {
    Stored,
    AlreadyExists,
    AuthenticationChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedPasskeyPersistenceResult {
    Stored,
    Conflict,
    AuthenticationChanged,
    IssuerChanged,
}

pub async fn insert_authenticated_totp_factor(
    pool: &PgPool,
    user_id: UserId,
    expected_session_epoch: i64,
    encrypted_secret: &[u8],
) -> Result<AuthenticatedTotpPersistenceResult, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    lock_factor_account(&mut transaction, user_id).await?;
    if !active_user_epoch_matches(&mut transaction, user_id, expected_session_epoch).await? {
        transaction.rollback().await?;
        return Ok(AuthenticatedTotpPersistenceResult::AuthenticationChanged);
    }
    let exists: bool = crate::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_totp_factors WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    if exists {
        transaction.commit().await?;
        return Ok(AuthenticatedTotpPersistenceResult::AlreadyExists);
    }
    crate::sqlx::query(
        "INSERT INTO user_totp_factors (user_id, encrypted_secret, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(encrypted_secret)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(AuthenticatedTotpPersistenceResult::Stored)
}

pub async fn insert_authenticated_passkey(
    pool: &PgPool,
    user_id: UserId,
    expected_session_epoch: i64,
    credential_id: &[u8],
    passkey: &Passkey,
) -> Result<AuthenticatedPasskeyPersistenceResult, crate::sqlx::Error> {
    insert_authenticated_passkey_with_generation(
        pool,
        user_id,
        expected_session_epoch,
        credential_id,
        passkey,
        None,
    )
    .await
}

pub async fn insert_authenticated_passkey_with_issuer_generation(
    pool: &PgPool,
    user_id: UserId,
    expected_session_epoch: i64,
    credential_id: &[u8],
    passkey: &Passkey,
    expected_issuer_generation: i64,
) -> Result<AuthenticatedPasskeyPersistenceResult, crate::sqlx::Error> {
    insert_authenticated_passkey_with_generation(
        pool,
        user_id,
        expected_session_epoch,
        credential_id,
        passkey,
        Some(expected_issuer_generation),
    )
    .await
}

async fn insert_authenticated_passkey_with_generation(
    pool: &PgPool,
    user_id: UserId,
    expected_session_epoch: i64,
    credential_id: &[u8],
    passkey: &Passkey,
    expected_issuer_generation: Option<i64>,
) -> Result<AuthenticatedPasskeyPersistenceResult, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::settings::repository::lock_passkey_policy(&mut transaction).await?;
    if let Some(expected) = expected_issuer_generation {
        let current: Option<i64> = crate::sqlx::query_scalar(
            "SELECT generation FROM app_settings WHERE setting_key = 'app_issuer'",
        )
        .fetch_optional(&mut *transaction)
        .await?;
        if !issuer_generation_matches(current, expected) {
            transaction.rollback().await?;
            return Ok(AuthenticatedPasskeyPersistenceResult::IssuerChanged);
        }
    }
    let enabled = match crate::settings::repository::get_text(
        &mut *transaction,
        crate::settings::PASSKEY_KEY,
    )
    .await?
    {
        None => true,
        Some(raw) => serde_json::from_str::<crate::settings::PasskeySetting>(&raw)
            .map(|setting| setting.enabled)
            .unwrap_or(false),
    };
    if !enabled {
        transaction.rollback().await?;
        return Ok(AuthenticatedPasskeyPersistenceResult::AuthenticationChanged);
    }
    lock_factor_account(&mut transaction, user_id).await?;
    if !active_user_epoch_matches(&mut transaction, user_id, expected_session_epoch).await? {
        transaction.rollback().await?;
        return Ok(AuthenticatedPasskeyPersistenceResult::AuthenticationChanged);
    }
    let credential = serde_json::to_value(passkey)
        .map_err(|error| crate::sqlx::Error::Encode(Box::new(error)))?;
    let result = crate::sqlx::query(
        "INSERT INTO user_passkeys
            (user_id, credential_id, credential, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (credential_id) DO NOTHING
         RETURNING user_id",
    )
    .bind(user_id)
    .bind(credential_id)
    .bind(credential)
    .fetch_optional(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(if result.is_some() {
        AuthenticatedPasskeyPersistenceResult::Stored
    } else {
        AuthenticatedPasskeyPersistenceResult::Conflict
    })
}

async fn active_user_epoch_matches(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    user_id: UserId,
    expected_session_epoch: i64,
) -> Result<bool, crate::sqlx::Error> {
    let state: Option<(i64, String)> =
        crate::sqlx::query_as("SELECT session_epoch, status FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut **transaction)
            .await?;
    Ok(state.is_some_and(|(epoch, status)| {
        epoch == expected_session_epoch
            && crate::users::domain::UserStatus::parse(&status)
                == Some(crate::users::domain::UserStatus::Active)
    }))
}
