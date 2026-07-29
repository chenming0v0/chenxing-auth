use crate::sqlx::PgPool;
use crate::users::domain::UserId;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

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
) -> Result<(), crate::sqlx::Error> {
    let credential = serde_json::to_value(passkey)
        .map_err(|error| crate::sqlx::Error::Encode(Box::new(error)))?;
    crate::sqlx::query(
        "INSERT INTO user_passkeys (id, user_id, credential_id, credential, created_at, updated_at)
         VALUES ($1, $2, $3, $4, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(credential_id)
    .bind(credential)
    .execute(pool)
    .await?;
    Ok(())
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
