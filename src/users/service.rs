use std::sync::Arc;

use thiserror::Error;

use super::{
    credentials::{hash_password, verify_password},
    domain::{
        LoginError, LoginInput, PublicUser, RegistrationError, RegistrationInput, UserId, UserRole,
        validate_display_name, validate_login, validate_registration,
    },
    repository,
};
use crate::{
    auth_limiter::{AuthFailureLimiter, FailureDimension},
    sqlx::PgPool,
};

#[derive(Clone)]
pub struct UserService {
    pool: PgPool,
    limiter: Arc<dyn AuthFailureLimiter>,
}

#[derive(Debug, Error)]
pub enum UserServiceError {
    #[error(transparent)]
    Validation(#[from] RegistrationError),
    #[error("could not hash password")]
    PasswordHash,
    #[error("could not persist user")]
    Database(#[from] crate::sqlx::Error),
    #[error("credentials are invalid")]
    InvalidCredentials,
    #[error("authentication rate limit reached")]
    RateLimited,
    #[error("authentication limiter failed: {0}")]
    Limiter(#[from] crate::auth_limiter::domain::AuthLimiterError),
    #[error("last active owner is required")]
    LastOwnerRequired,
    #[error("owner bootstrap is required before public registration")]
    OwnerBootstrapRequired,
}

impl UserService {
    pub fn new(pool: PgPool, limiter: Arc<dyn AuthFailureLimiter>) -> Self {
        Self { pool, limiter }
    }

    pub async fn register(&self, input: RegistrationInput) -> Result<PublicUser, UserServiceError> {
        let registration = validate_registration(input)?;
        let password_hash =
            hash_password(&registration.password).map_err(|_| UserServiceError::PasswordHash)?;
        let Some(user) =
            repository::insert_user_after_owner(&self.pool, registration, password_hash).await?
        else {
            return Err(UserServiceError::OwnerBootstrapRequired);
        };

        Ok(PublicUser {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name: user.display_name,
            status: "active".to_owned(),
            role: super::domain::UserRole::User,
            created_at: user.created_at,
        })
    }

    pub async fn bootstrap_owner(
        &self,
        input: RegistrationInput,
    ) -> Result<BootstrapOwnerResult, UserServiceError> {
        let registration = validate_registration(input)?;
        let password_hash =
            hash_password(&registration.password).map_err(|_| UserServiceError::PasswordHash)?;
        Ok(
            match repository::bootstrap_owner(
                &self.pool,
                &registration.username,
                &registration.email,
                &password_hash,
            )
            .await?
            {
                repository::BootstrapOwnerOutcome::Created(profile) => {
                    BootstrapOwnerResult::Created(profile)
                }
                repository::BootstrapOwnerOutcome::AlreadyConfigured => {
                    BootstrapOwnerResult::AlreadyConfigured
                }
                repository::BootstrapOwnerOutcome::RequiresEmptyDatabase => {
                    BootstrapOwnerResult::RequiresEmptyDatabase
                }
            },
        )
    }

    pub async fn owner_initialized(&self) -> Result<bool, UserServiceError> {
        Ok(
            crate::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner')")
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn create_privileged(
        &self,
        input: RegistrationInput,
        role: UserRole,
    ) -> Result<UserId, UserServiceError> {
        let registration = validate_registration(input)?;
        let password_hash =
            hash_password(&registration.password).map_err(|_| UserServiceError::PasswordHash)?;
        let Some(id) = repository::insert_user_with_role(
            &self.pool,
            &registration.username,
            &registration.email,
            &password_hash,
            role,
        )
        .await?
        else {
            return Err(UserServiceError::OwnerBootstrapRequired);
        };
        Ok(id)
    }

    pub async fn authenticate(
        &self,
        input: LoginInput,
        source_ip: &str,
    ) -> Result<UserId, UserServiceError> {
        let login = validate_login(input).map_err(|error| match error {
            LoginError::InvalidIdentifier | LoginError::EmptyPassword => {
                UserServiceError::InvalidCredentials
            }
        })?;
        self.ensure_allowed(FailureDimension::Account, &login.identifier)
            .await?;
        self.ensure_allowed(FailureDimension::SourceIp, source_ip)
            .await?;
        let Some(credentials) =
            repository::find_credentials_by_identifier(&self.pool, &login.identifier).await?
        else {
            self.record_failure(&login.identifier, source_ip).await?;
            return Err(UserServiceError::InvalidCredentials);
        };
        if credentials.status != "active"
            || !credentials.password_login_enabled
            || !verify_password(&login.password, &credentials.password_hash)
        {
            self.record_failure(&login.identifier, source_ip).await?;
            return Err(UserServiceError::InvalidCredentials);
        }

        self.limiter
            .clear(FailureDimension::Account, &login.identifier)
            .await?;
        Ok(credentials.id)
    }

    async fn ensure_allowed(
        &self,
        dimension: FailureDimension,
        value: &str,
    ) -> Result<(), UserServiceError> {
        if self.limiter.is_limited(dimension, value).await? {
            return Err(UserServiceError::RateLimited);
        }
        Ok(())
    }

    async fn record_failure(
        &self,
        identifier: &str,
        source_ip: &str,
    ) -> Result<(), UserServiceError> {
        self.limiter
            .record_failure(FailureDimension::Account, identifier)
            .await?;
        self.limiter
            .record_failure(FailureDimension::SourceIp, source_ip)
            .await?;
        Ok(())
    }

    pub async fn find_profile(
        &self,
        id: UserId,
    ) -> Result<Option<repository::UserProfile>, UserServiceError> {
        Ok(repository::find_profile_by_id(&self.pool, id).await?)
    }

    pub async fn update_display_name(
        &self,
        id: UserId,
        display_name: Option<String>,
    ) -> Result<Option<repository::UserProfile>, UserServiceError> {
        let display_name = validate_display_name(display_name)?;
        if !repository::update_display_name(&self.pool, id, display_name.as_deref()).await? {
            return Ok(None);
        }
        Ok(repository::find_profile_by_id(&self.pool, id).await?)
    }

    pub async fn change_password(
        &self,
        id: UserId,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), UserServiceError> {
        if new_password.chars().count() < crate::users::domain::MIN_PASSWORD_LENGTH {
            return Err(UserServiceError::Validation(
                RegistrationError::PasswordTooShort,
            ));
        }
        let Some(credentials) = repository::find_credentials_by_id(&self.pool, id).await? else {
            return Err(UserServiceError::InvalidCredentials);
        };
        if credentials.status != "active"
            || !verify_password(current_password, &credentials.password_hash)
        {
            return Err(UserServiceError::InvalidCredentials);
        }
        let password_hash =
            hash_password(new_password).map_err(|_| UserServiceError::PasswordHash)?;
        if !repository::update_password_hash(&self.pool, id, &password_hash).await? {
            return Err(UserServiceError::InvalidCredentials);
        }
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<repository::ListedUser>, UserServiceError> {
        Ok(repository::list_users(&self.pool).await?)
    }

    pub async fn set_status(&self, id: UserId, status: &str) -> Result<bool, UserServiceError> {
        if !matches!(status, "active" | "disabled") {
            return Ok(false);
        }
        Ok(repository::set_user_status(&self.pool, id, status).await?)
    }

    pub async fn set_role(&self, id: UserId, role: UserRole) -> Result<bool, UserServiceError> {
        match repository::set_user_role(&self.pool, id, role).await {
            Ok(value) => Ok(value),
            Err(crate::sqlx::Error::Protocol(message)) if message.contains("last active owner") => {
                Err(UserServiceError::LastOwnerRequired)
            }
            Err(error) => Err(UserServiceError::Database(error)),
        }
    }

    pub async fn set_status_guarded(
        &self,
        id: UserId,
        status: &str,
    ) -> Result<bool, UserServiceError> {
        if !matches!(status, "active" | "disabled") {
            return Ok(false);
        }
        match repository::set_user_status_guarded(&self.pool, id, status).await? {
            Some("last_owner_required") => Err(UserServiceError::LastOwnerRequired),
            Some("updated") => Ok(true),
            _ => Ok(false),
        }
    }
}

#[derive(Debug)]
pub enum BootstrapOwnerResult {
    Created(repository::UserProfile),
    AlreadyConfigured,
    RequiresEmptyDatabase,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::auth_limiter::{AuthFailureLimiter, FailureDimension};
    use crate::auth_limiter::domain::LimiterFuture;

    struct AlwaysLimited;

    impl AuthFailureLimiter for AlwaysLimited {
        fn is_limited<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &'a str,
        ) -> LimiterFuture<'a, bool> {
            Box::pin(async { Ok(true) })
        }

        fn record_failure<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &'a str,
        ) -> LimiterFuture<'a, bool> {
            Box::pin(async { Ok(false) })
        }

        fn clear<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &'a str,
        ) -> LimiterFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn password_authentication_is_rejected_before_password_hash() {
        let pool = crate::sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid-host/unused")
            .expect("lazy pool");
        let service = UserService::new(pool, Arc::new(AlwaysLimited));
        let result = service
            .authenticate(
                LoginInput {
                    identifier: "user@example.com".to_owned(),
                    password: "incorrect password".to_owned(),
                    totp_code: None,
                },
                "127.0.0.1",
            )
            .await;
        assert!(matches!(result, Err(UserServiceError::RateLimited)));
    }
}
