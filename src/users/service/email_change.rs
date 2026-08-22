use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::UserService;
use crate::notifications::crypto::encrypt_code;
use crate::users::{
    credentials::{hash_password, verify_password},
    domain::UserId,
    email::EmailAddress,
    repository,
};

const CHALLENGE_LIFETIME_MINUTES: i64 = 10;
pub const EMAIL_CHANGE_FAILED_ATTEMPT_LIMIT: i64 = 5;

#[derive(Debug, thiserror::Error)]
pub enum EmailChangeError {
    #[error("email address is invalid")]
    InvalidEmail,
    #[error("email domain is not allowed")]
    EmailNotAllowed,
    #[error("current password is invalid")]
    InvalidCredentials,
    #[error("password reauthentication is unavailable")]
    ReauthenticationUnavailable,
    #[error("email change encryption is unavailable")]
    EncryptionUnavailable,
    #[error("email change challenge is invalid")]
    InvalidChallenge,
    #[error("email change code is invalid")]
    InvalidCode,
    #[error("email change confirmation rate limit reached")]
    RateLimited,
    #[error("target email is already registered")]
    EmailConflict,
    #[error("authentication state changed")]
    AuthenticationChanged,
    #[error("email change persistence failed")]
    Database(#[from] crate::sqlx::Error),
    #[error("email change credential hashing failed")]
    CredentialHash,
    #[error("authentication limiter failed")]
    Limiter,
}

pub struct EmailChangeStart {
    pub challenge_id: Uuid,
    pub expires_at: OffsetDateTime,
}

pub struct EmailChangeConfirmation {
    pub old_email: EmailAddress,
}

impl UserService {
    pub async fn start_email_change(
        &self,
        user_id: UserId,
        new_email: &str,
        current_password: &str,
        source_ip: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<EmailChangeStart, EmailChangeError> {
        let new_email =
            EmailAddress::parse(new_email).map_err(|_| EmailChangeError::InvalidEmail)?;
        crate::users::email_policy::ensure_email_policy_allows(&self.pool, &new_email)
            .await
            .map_err(|error| match error {
                super::UserServiceError::EmailDomainNotAllowed => EmailChangeError::EmailNotAllowed,
                super::UserServiceError::Database(error) => EmailChangeError::Database(error),
                _ => EmailChangeError::EmailNotAllowed,
            })?;
        let authenticated = self
            .reauthenticate_password(user_id, current_password, source_ip)
            .await
            .map_err(map_reauthentication_error)?
            .ok_or(EmailChangeError::ReauthenticationUnavailable)?;
        let code = Zeroizing::new(format!("{:06}", rand::random::<u32>() % 1_000_000));
        let code_hash = hash_password(code.as_str().to_owned())
            .await
            .map_err(|_| EmailChangeError::CredentialHash)?;
        let challenge_id = Uuid::new_v4();
        let expires_at = now + time::Duration::minutes(CHALLENGE_LIFETIME_MINUTES);
        let encryption_keys = self
            .email_encryption_keys
            .as_ref()
            .ok_or(EmailChangeError::EncryptionUnavailable)?;
        let encrypted_code = encrypt_code(encryption_keys, code.as_str(), user_id, challenge_id)
            .map_err(|_| EmailChangeError::EncryptionUnavailable)?;
        let outcome = repository::email_change::replace_pending_email_change(
            &self.pool,
            challenge_id,
            user_id,
            &new_email,
            &code_hash,
            encrypted_code.as_slice(),
            authenticated.session_epoch,
            expires_at,
        )
        .await?;
        if outcome != repository::email_change::EmailChangeStartOutcome::Created {
            return Err(EmailChangeError::AuthenticationChanged);
        }
        Ok(EmailChangeStart {
            challenge_id,
            expires_at,
        })
    }

    pub async fn confirm_email_change(
        &self,
        user_id: UserId,
        challenge_id: Uuid,
        code: &str,
    ) -> Result<EmailChangeConfirmation, EmailChangeError> {
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(EmailChangeError::InvalidChallenge);
        }
        let challenge = match repository::email_change::reserve_email_change_attempt(
            &self.pool,
            challenge_id,
            user_id,
            EMAIL_CHANGE_FAILED_ATTEMPT_LIMIT,
        )
        .await
        {
            Ok(Some(challenge)) => challenge,
            Ok(None) => return Err(EmailChangeError::InvalidChallenge),
            Err(error) => return Err(error.into()),
        };
        if !verify_password(code.to_owned(), challenge.code_hash.clone()).await {
            let failure = match repository::email_change::record_email_change_failure(
                &self.pool,
                challenge_id,
                user_id,
                challenge.attempt_id,
                EMAIL_CHANGE_FAILED_ATTEMPT_LIMIT,
            )
            .await
            {
                Ok(Some(result)) => result,
                Ok(None) => {
                    release_email_change_attempt_after_error(
                        self,
                        challenge_id,
                        user_id,
                        challenge.attempt_id,
                    )
                    .await;
                    return Err(EmailChangeError::InvalidChallenge);
                }
                Err(error) => {
                    release_email_change_attempt_after_error(
                        self,
                        challenge_id,
                        user_id,
                        challenge.attempt_id,
                    )
                    .await;
                    return Err(error.into());
                }
            };
            if failure.threshold_reached {
                return Err(EmailChangeError::RateLimited);
            }
            if failure.challenge_consumed {
                return Err(EmailChangeError::InvalidChallenge);
            }
            return Err(EmailChangeError::InvalidCode);
        }

        // The expensive hash check is outside the account transaction. The
        // challenge's in-flight slot keeps the budget bounded while this runs.
        complete_email_change(self, user_id, challenge_id, challenge).await
    }
}

async fn complete_email_change(
    service: &UserService,
    user_id: UserId,
    challenge_id: Uuid,
    challenge: repository::email_change::LockedEmailChangeChallenge,
) -> Result<EmailChangeConfirmation, EmailChangeError> {
    let result = async {
        let mut transaction = service.pool.begin().await?;
        crate::sessions::store::lock_user_session_scope(&mut transaction, user_id).await?;
        let (old_email, current_epoch) =
            repository::email_change::current_email_and_epoch(&mut transaction, user_id)
                .await?
                .ok_or(EmailChangeError::AuthenticationChanged)?;
        if current_epoch != challenge.security_epoch {
            return Err(EmailChangeError::AuthenticationChanged);
        }
        if repository::email_change::target_email_is_taken(
            &mut transaction,
            user_id,
            &challenge.new_canonical_email,
        )
        .await?
        {
            return Err(EmailChangeError::EmailConflict);
        }
        if !repository::email_change::consume_email_change_attempt(
            &mut transaction,
            challenge_id,
            user_id,
            challenge.attempt_id,
        )
        .await?
        {
            return Err(EmailChangeError::InvalidChallenge);
        }
        repository::email_change::apply_email_change(
            &mut transaction,
            user_id,
            &challenge.new_email,
            &challenge.new_canonical_email,
        )
        .await?;
        crate::sessions::store::revoke_all_for_user_in_transaction(&mut transaction, user_id)
            .await?
            .ok_or(EmailChangeError::AuthenticationChanged)?;
        let old_email =
            EmailAddress::parse(&old_email).map_err(|_| EmailChangeError::AuthenticationChanged)?;
        repository::email_change::enqueue_email_change_security_alert(
            &mut transaction,
            user_id,
            challenge_id,
            &old_email,
        )
        .await?;
        transaction.commit().await?;
        Ok(EmailChangeConfirmation { old_email })
    }
    .await;

    if result.is_err() {
        // The attempt UUID makes this compensation idempotent and ownership
        // bound. It is safe even when commit returned an ambiguous error: a
        // committed transaction already removed this UUID, while a rollback
        // leaves exactly this UUID for the compensating update.
        release_email_change_attempt_after_error(
            service,
            challenge_id,
            user_id,
            challenge.attempt_id,
        )
        .await;
    }
    result
}

async fn release_email_change_attempt_after_error(
    service: &UserService,
    challenge_id: Uuid,
    user_id: UserId,
    attempt_id: Uuid,
) {
    if let Err(error) = repository::email_change::release_email_change_attempt(
        &service.pool,
        challenge_id,
        user_id,
        attempt_id,
        EMAIL_CHANGE_FAILED_ATTEMPT_LIMIT,
    )
    .await
    {
        tracing::error!(
            error = %error,
            challenge_id = %challenge_id,
            user_id,
            "failed to release email change verification slot"
        );
    }
}

fn map_reauthentication_error(error: super::UserServiceError) -> EmailChangeError {
    match error {
        super::UserServiceError::InvalidCredentials => EmailChangeError::InvalidCredentials,
        super::UserServiceError::PasswordReauthenticationUnavailable => {
            EmailChangeError::ReauthenticationUnavailable
        }
        super::UserServiceError::Database(error) => EmailChangeError::Database(error),
        super::UserServiceError::Limiter(_) | super::UserServiceError::RateLimited => {
            EmailChangeError::Limiter
        }
        _ => EmailChangeError::InvalidCredentials,
    }
}
