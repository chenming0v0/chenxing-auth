use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use super::UserService;
use crate::{
    notifications::{EmailMessage, EmailSender},
    users::{
        credentials::{hash_password, verify_password},
        domain::UserId,
        email::EmailAddress,
        repository,
    },
};

const CHALLENGE_LIFETIME_MINUTES: i64 = 10;

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
    #[error("email delivery is unavailable")]
    DeliveryUnavailable,
    #[error("email change challenge is invalid")]
    InvalidChallenge,
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
        sender: Arc<dyn EmailSender>,
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
        let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
        let code_hash = hash_password(code.clone())
            .await
            .map_err(|_| EmailChangeError::CredentialHash)?;
        let challenge_id = Uuid::new_v4();
        let expires_at = now + time::Duration::minutes(CHALLENGE_LIFETIME_MINUTES);
        sender
            .send(EmailMessage {
                to: new_email.clone(),
                subject: "辰星通行证邮箱变更验证码".to_owned(),
                body: format!(
                    "你的邮箱变更验证码是：{code}\n验证码将在 {CHALLENGE_LIFETIME_MINUTES} 分钟后失效。"
                ),
            })
            .await
            .map_err(|_| EmailChangeError::DeliveryUnavailable)?;
        repository::email_change::replace_pending_email_change(
            &self.pool,
            challenge_id,
            user_id,
            &new_email,
            &code_hash,
            authenticated.session_epoch,
            expires_at,
        )
        .await?;
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
        let mut transaction = self.pool.begin().await?;
        crate::sessions::store::lock_user_session_scope(&mut transaction, user_id).await?;
        let challenge = repository::email_change::lock_email_change_challenge(
            &mut transaction,
            challenge_id,
            user_id,
        )
        .await?
        .ok_or(EmailChangeError::InvalidChallenge)?;
        if !verify_password(code.to_owned(), challenge.code_hash).await {
            return Err(EmailChangeError::InvalidChallenge);
        }
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
        repository::email_change::apply_email_change(
            &mut transaction,
            challenge_id,
            user_id,
            &challenge.new_email,
            &challenge.new_canonical_email,
        )
        .await?;
        crate::sessions::store::revoke_all_for_user_in_transaction(&mut transaction, user_id)
            .await?
            .ok_or(EmailChangeError::AuthenticationChanged)?;
        transaction.commit().await?;
        let old_email =
            EmailAddress::parse(&old_email).map_err(|_| EmailChangeError::AuthenticationChanged)?;
        Ok(EmailChangeConfirmation { old_email })
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
