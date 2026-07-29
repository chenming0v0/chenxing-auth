use crate::sqlx::PgPool;
use thiserror::Error;

use super::{
    credentials::{hash_password, verify_password},
    domain::{
        LoginError, LoginInput, PublicUser, RegistrationError, RegistrationInput, UserId,
        validate_display_name, validate_login, validate_registration,
    },
    repository,
};

#[derive(Clone)]
pub struct UserService {
    pool: PgPool,
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
}

impl UserService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn register(&self, input: RegistrationInput) -> Result<PublicUser, UserServiceError> {
        let registration = validate_registration(input)?;
        let password_hash =
            hash_password(&registration.password).map_err(|_| UserServiceError::PasswordHash)?;
        let user = repository::insert_user(&self.pool, registration, password_hash).await?;

        Ok(PublicUser {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name: user.display_name,
            status: "active".to_owned(),
            created_at: user.created_at,
        })
    }

    pub async fn authenticate(&self, input: LoginInput) -> Result<UserId, UserServiceError> {
        let login = validate_login(input).map_err(|error| match error {
            LoginError::InvalidIdentifier | LoginError::EmptyPassword => {
                UserServiceError::InvalidCredentials
            }
        })?;
        let Some(credentials) =
            repository::find_credentials_by_identifier(&self.pool, &login.identifier).await?
        else {
            return Err(UserServiceError::InvalidCredentials);
        };
        if credentials.status != "active"
            || !credentials.password_login_enabled
            || !verify_password(&login.password, &credentials.password_hash)
        {
            return Err(UserServiceError::InvalidCredentials);
        }

        Ok(credentials.id)
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
}
