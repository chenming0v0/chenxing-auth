use time::OffsetDateTime;
use uuid::Uuid;

use crate::sqlx::{PgPool, Postgres, Transaction};
use crate::users::{domain::UserId, email::EmailAddress};

pub struct LockedEmailChangeChallenge {
    pub new_email: String,
    pub new_canonical_email: String,
    pub code_hash: String,
    pub security_epoch: i64,
}

pub async fn replace_pending_email_change(
    pool: &PgPool,
    challenge_id: Uuid,
    user_id: UserId,
    new_email: &EmailAddress,
    code_hash: &str,
    security_epoch: i64,
    expires_at: OffsetDateTime,
) -> Result<(), crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sessions::store::lock_user_session_scope(&mut transaction, user_id).await?;
    crate::sqlx::query(
        "UPDATE user_email_change_challenges SET consumed_at = NOW()
         WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    crate::sqlx::query(
        "INSERT INTO user_email_change_challenges
             (id, user_id, new_email, new_canonical_email, code_hash,
              security_epoch, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(challenge_id)
    .bind(user_id)
    .bind(new_email.display())
    .bind(new_email.canonical())
    .bind(code_hash)
    .bind(security_epoch)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await
}

pub async fn lock_email_change_challenge<'a>(
    transaction: &mut Transaction<'a, Postgres>,
    challenge_id: Uuid,
    user_id: UserId,
) -> Result<Option<LockedEmailChangeChallenge>, crate::sqlx::Error> {
    crate::sqlx::query_as::<_, (String, String, String, i64)>(
        "SELECT new_email, new_canonical_email, code_hash, security_epoch
         FROM user_email_change_challenges
         WHERE id = $1 AND user_id = $2 AND consumed_at IS NULL
           AND expires_at > NOW()
         FOR UPDATE",
    )
    .bind(challenge_id)
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await
    .map(|row| {
        row.map(
            |(new_email, new_canonical_email, code_hash, security_epoch)| {
                LockedEmailChangeChallenge {
                    new_email,
                    new_canonical_email,
                    code_hash,
                    security_epoch,
                }
            },
        )
    })
}

pub async fn current_email_and_epoch(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
) -> Result<Option<(String, i64)>, crate::sqlx::Error> {
    crate::sqlx::query_as("SELECT email, session_epoch FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .fetch_optional(&mut **transaction)
        .await
}

pub async fn target_email_is_taken(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
    canonical_email: &str,
) -> Result<bool, crate::sqlx::Error> {
    crate::sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE canonical_email = $1 AND id <> $2)",
    )
    .bind(canonical_email)
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await
}

pub async fn apply_email_change(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
    user_id: UserId,
    new_email: &str,
    new_canonical_email: &str,
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query(
        "UPDATE users SET email = $2, canonical_email = $3, updated_at = NOW()
         WHERE id = $1",
    )
    .bind(user_id)
    .bind(new_email)
    .bind(new_canonical_email)
    .execute(&mut **transaction)
    .await?;
    crate::sqlx::query("UPDATE user_email_change_challenges SET consumed_at = NOW() WHERE id = $1")
        .bind(challenge_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}
