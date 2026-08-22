use time::OffsetDateTime;
use uuid::Uuid;

use crate::sqlx::{PgPool, Postgres, Transaction};
use crate::users::{domain::UserId, email::EmailAddress};

pub struct LockedEmailChangeChallenge {
    pub attempt_id: Uuid,
    pub new_email: String,
    pub new_canonical_email: String,
    pub code_hash: String,
    pub security_epoch: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailChangeStartOutcome {
    Created,
    AuthenticationChanged,
}

pub struct RecordedEmailChangeFailure {
    pub challenge_consumed: bool,
    pub threshold_reached: bool,
}

/// Atomically reserve one verification slot before doing Argon2 work.
///
/// `in_flight_attempts` is separate from `failed_attempts`: a correct code that
/// races with wrong guesses must still be able to finish before the failed
/// budget is exhausted. Both counters are changed only by guarded updates.
pub async fn reserve_email_change_attempt(
    pool: &PgPool,
    challenge_id: Uuid,
    user_id: UserId,
    max_failed_attempts: i64,
) -> Result<Option<LockedEmailChangeChallenge>, crate::sqlx::Error> {
    let attempt_id = Uuid::new_v4();
    crate::sqlx::query_as::<_, (String, String, String, i64)>(
        "UPDATE user_email_change_challenges
         SET in_flight_attempts = in_flight_attempts + 1,
             active_attempt_ids = array_append(active_attempt_ids, $4)
         WHERE id = $1 AND user_id = $2 AND consumed_at IS NULL
           AND expires_at > NOW()
           AND failed_attempts < $3
           AND in_flight_attempts < $3
           AND in_flight_attempts = cardinality(active_attempt_ids)
         RETURNING new_email, new_canonical_email, code_hash, security_epoch",
    )
    .bind(challenge_id)
    .bind(user_id)
    .bind(max_failed_attempts)
    .bind(attempt_id)
    .fetch_optional(pool)
    .await
    .map(|row| {
        row.map(
            |(new_email, new_canonical_email, code_hash, security_epoch)| {
                LockedEmailChangeChallenge {
                    attempt_id,
                    new_email,
                    new_canonical_email,
                    code_hash,
                    security_epoch,
                }
            },
        )
    })
}

/// Commit a wrong code and invalidate the challenge at the threshold.
///
/// `None` means the request did not own an active slot. The returned state
/// distinguishes a threshold invalidation from a prior successful consumption.
pub async fn record_email_change_failure(
    pool: &PgPool,
    challenge_id: Uuid,
    user_id: UserId,
    attempt_id: Uuid,
    max_failed_attempts: i64,
) -> Result<Option<RecordedEmailChangeFailure>, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let previous = crate::sqlx::query_as::<_, (bool, i64, i64)>(
        "SELECT consumed_at IS NOT NULL, failed_attempts, in_flight_attempts
         FROM user_email_change_challenges
         WHERE id = $1 AND user_id = $2
           AND in_flight_attempts > 0
           AND $3 = ANY(active_attempt_ids)
         FOR UPDATE",
    )
    .bind(challenge_id)
    .bind(user_id)
    .bind(attempt_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((was_consumed, previous_failed_attempts, previous_in_flight_attempts)) = previous
    else {
        return Ok(None);
    };

    let challenge_consumed = crate::sqlx::query_scalar::<_, bool>(
        "UPDATE user_email_change_challenges
         SET in_flight_attempts = in_flight_attempts - 1,
             active_attempt_ids = array_remove(active_attempt_ids, $3),
             failed_attempts = CASE
                 WHEN consumed_at IS NULL THEN LEAST(failed_attempts + 1, $4)
                 ELSE failed_attempts
             END,
             consumed_at = CASE
                 WHEN consumed_at IS NULL
                   AND failed_attempts + 1 >= $4
                   AND in_flight_attempts = 1
                     THEN NOW()
                 ELSE consumed_at
             END
         WHERE id = $1 AND user_id = $2
           AND in_flight_attempts > 0
           AND $3 = ANY(active_attempt_ids)
         RETURNING consumed_at IS NOT NULL",
    )
    .bind(challenge_id)
    .bind(user_id)
    .bind(attempt_id)
    .bind(max_failed_attempts)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(Some(RecordedEmailChangeFailure {
        challenge_consumed,
        threshold_reached: !was_consumed
            && previous_failed_attempts < max_failed_attempts
            && previous_failed_attempts + 1 >= max_failed_attempts
            && previous_in_flight_attempts == 1,
    }))
}

/// Release a reserved slot after the account transaction definitely rolled
/// back. A consumed challenge may still have concurrent slots to drain, so the
/// update deliberately works after `consumed_at` is set.
pub async fn release_email_change_attempt(
    pool: &PgPool,
    challenge_id: Uuid,
    user_id: UserId,
    attempt_id: Uuid,
    max_failed_attempts: i64,
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query(
        "UPDATE user_email_change_challenges
         SET in_flight_attempts = in_flight_attempts - 1,
             active_attempt_ids = array_remove(active_attempt_ids, $3),
             consumed_at = CASE
                 WHEN consumed_at IS NULL
                   AND failed_attempts >= $4
                   AND in_flight_attempts = 1
                     THEN NOW()
                 ELSE consumed_at
             END
         WHERE id = $1 AND user_id = $2 AND in_flight_attempts > 0
           AND $3 = ANY(active_attempt_ids)",
    )
    .bind(challenge_id)
    .bind(user_id)
    .bind(attempt_id)
    .bind(max_failed_attempts)
    .execute(pool)
    .await
    .map(|_| ())
}

/// Consume the slot reserved by the successful code. This is the final
/// challenge CAS and is kept in the same PostgreSQL transaction as the email
/// update and session revocation.
pub async fn consume_email_change_attempt<'a>(
    transaction: &mut Transaction<'a, Postgres>,
    challenge_id: Uuid,
    user_id: UserId,
    attempt_id: Uuid,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE user_email_change_challenges
         SET in_flight_attempts = in_flight_attempts - 1,
             active_attempt_ids = array_remove(active_attempt_ids, $3),
             consumed_at = NOW()
         WHERE id = $1 AND user_id = $2 AND consumed_at IS NULL
           AND in_flight_attempts > 0
           AND $3 = ANY(active_attempt_ids)",
    )
    .bind(challenge_id)
    .bind(user_id)
    .bind(attempt_id)
    .execute(&mut **transaction)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn replace_pending_email_change(
    pool: &PgPool,
    challenge_id: Uuid,
    user_id: UserId,
    new_email: &EmailAddress,
    code_hash: &str,
    encrypted_code: &[u8],
    security_epoch: i64,
    expires_at: OffsetDateTime,
) -> Result<EmailChangeStartOutcome, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sessions::store::lock_user_session_scope(&mut transaction, user_id).await?;
    let current_epoch: Option<i64> =
        crate::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?;
    if current_epoch != Some(security_epoch) {
        transaction.rollback().await?;
        return Ok(EmailChangeStartOutcome::AuthenticationChanged);
    }
    crate::sqlx::query(
        "UPDATE user_email_change_challenges SET consumed_at = NOW()
         WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    crate::sqlx::query(
        "UPDATE email_outbox SET cancelled_at = NOW(), claim_token = '', last_error = NULL
         WHERE user_id = $1 AND processed_at IS NULL
           AND cancelled_at IS NULL AND dead_lettered_at IS NULL
           AND kind = 'verification_code'",
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
    crate::sqlx::query(
        "INSERT INTO email_outbox
             (user_id, challenge_id, encrypted_code, kind)
         VALUES ($1, $2, $3, 'verification_code')",
    )
    .bind(user_id)
    .bind(challenge_id)
    .bind(encrypted_code)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(EmailChangeStartOutcome::Created)
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
    crate::sqlx::query(
        "UPDATE email_outbox SET cancelled_at = NOW(), claim_token = '', last_error = NULL
         WHERE user_id = $1 AND processed_at IS NULL
           AND cancelled_at IS NULL AND dead_lettered_at IS NULL
           AND kind = 'verification_code'",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub async fn enqueue_email_change_security_alert(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
    challenge_id: Uuid,
    recipient: &EmailAddress,
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query(
        "INSERT INTO email_outbox (user_id, challenge_id, kind, recipient)
         VALUES ($1, $2, 'email_change_security_alert', $3)
         ON CONFLICT (challenge_id, kind) DO NOTHING",
    )
    .bind(user_id)
    .bind(challenge_id)
    .bind(recipient.display())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
