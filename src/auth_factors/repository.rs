use crate::sqlx::PgPool;
use crate::users::domain::UserId;
use webauthn_rs::prelude::Passkey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyPersistenceResult {
    Stored,
    Conflict,
}

pub async fn insert_totp_factor(
    pool: &PgPool,
    user_id: UserId,
    encrypted_secret: &[u8],
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query(
        "INSERT INTO user_totp_factors (user_id, encrypted_secret, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (user_id) DO UPDATE
         SET encrypted_secret = EXCLUDED.encrypted_secret, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(encrypted_secret)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstFactorPersistenceResult {
    Stored,
    AlreadyExists,
}

pub async fn insert_totp_factor_if_empty(
    pool: &PgPool,
    user_id: UserId,
    encrypted_secret: &[u8],
) -> Result<FirstFactorPersistenceResult, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    lock_factor_account(&mut transaction, user_id).await?;
    if account_has_factor(&mut transaction, user_id).await? {
        transaction.commit().await?;
        return Ok(FirstFactorPersistenceResult::AlreadyExists);
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
    Ok(FirstFactorPersistenceResult::Stored)
}

pub async fn insert_totp_factor_for_passkey_recovery(
    pool: &PgPool,
    user_id: UserId,
    encrypted_secret: &[u8],
) -> Result<FirstFactorPersistenceResult, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    lock_factor_account(&mut transaction, user_id).await?;
    let passkey_only: bool = crate::sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM user_passkeys WHERE user_id = $1
         ) AND NOT EXISTS(
             SELECT 1 FROM user_totp_factors WHERE user_id = $1
         )",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !passkey_only {
        transaction.commit().await?;
        return Ok(FirstFactorPersistenceResult::AlreadyExists);
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
    Ok(FirstFactorPersistenceResult::Stored)
}

pub async fn update_totp_factor_if_current(
    pool: &PgPool,
    user_id: UserId,
    current_ciphertext: &[u8],
    replacement_ciphertext: &[u8],
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE user_totp_factors
         SET encrypted_secret = $3, updated_at = NOW()
         WHERE user_id = $1 AND encrypted_secret = $2",
    )
    .bind(user_id)
    .bind(current_ciphertext)
    .bind(replacement_ciphertext)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn find_totp_secret(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Option<Vec<u8>>, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT encrypted_secret FROM user_totp_factors WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

pub async fn list_factor_methods(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Vec<String>, crate::sqlx::Error> {
    let rows = crate::sqlx::query_as::<_, (String,)>(
        "SELECT method FROM (
             SELECT 'totp'::text AS method FROM user_totp_factors WHERE user_id = $1
             UNION ALL
             SELECT 'passkey'::text AS method FROM user_passkeys WHERE user_id = $1
         ) methods ORDER BY method",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(method,)| method).collect())
}

pub async fn has_active_passkey_only_accounts(
    pool: &PgPool,
) -> Result<bool, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
             FROM users
             WHERE status = 'active'
               AND EXISTS (
                   SELECT 1 FROM user_passkeys WHERE user_passkeys.user_id = users.id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM user_totp_factors WHERE user_totp_factors.user_id = users.id
               )
         )",
    )
    .fetch_one(pool)
    .await
}

pub async fn list_passkeys(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Vec<Passkey>, crate::sqlx::Error> {
    let rows = crate::sqlx::query_as::<_, (serde_json::Value,)>(
        "SELECT credential FROM user_passkeys WHERE user_id = $1 ORDER BY created_at ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(value,)| {
            serde_json::from_value(value)
                .map_err(|error| crate::sqlx::Error::Decode(Box::new(error)))
        })
        .collect()
}

pub async fn insert_passkey(
    pool: &PgPool,
    user_id: UserId,
    credential_id: &[u8],
    passkey: &Passkey,
) -> Result<PasskeyPersistenceResult, crate::sqlx::Error> {
    let credential = serde_json::to_value(passkey)
        .map_err(|error| crate::sqlx::Error::Encode(Box::new(error)))?;
    let result = crate::sqlx::query(
        "INSERT INTO user_passkeys AS existing
            (user_id, credential_id, credential, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (credential_id) DO UPDATE
         SET credential = EXCLUDED.credential
         WHERE existing.user_id = EXCLUDED.user_id
           AND existing.credential = EXCLUDED.credential
         RETURNING user_id",
    )
    .bind(user_id)
    .bind(credential_id)
    .bind(credential)
    .fetch_optional(pool)
    .await?;
    Ok(if result.is_some() {
        PasskeyPersistenceResult::Stored
    } else {
        PasskeyPersistenceResult::Conflict
    })
}

pub async fn insert_passkey_if_empty(
    pool: &PgPool,
    user_id: UserId,
    credential_id: &[u8],
    passkey: &Passkey,
) -> Result<PasskeyPersistenceResult, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    lock_factor_account(&mut transaction, user_id).await?;
    if account_has_factor(&mut transaction, user_id).await? {
        transaction.commit().await?;
        return Ok(PasskeyPersistenceResult::Conflict);
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
        PasskeyPersistenceResult::Stored
    } else {
        PasskeyPersistenceResult::Conflict
    })
}

pub async fn update_passkey(
    pool: &PgPool,
    credential_id: &[u8],
    passkey: &Passkey,
) -> Result<bool, crate::sqlx::Error> {
    let credential = serde_json::to_value(passkey)
        .map_err(|error| crate::sqlx::Error::Encode(Box::new(error)))?;
    let result = crate::sqlx::query(
        "UPDATE user_passkeys SET credential = $2, updated_at = NOW() WHERE credential_id = $1",
    )
    .bind(credential_id)
    .bind(credential)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn lock_factor_account(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    user_id: UserId,
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn account_has_factor(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    user_id: UserId,
) -> Result<bool, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM user_totp_factors WHERE user_id = $1
             UNION ALL
             SELECT 1 FROM user_passkeys WHERE user_id = $1
         )",
    )
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await
}
