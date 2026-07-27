use sqlx::PgPool;
use thiserror::Error;

use super::{
    credentials::{hash_password, verify_password},
    domain::{
        LoginError, LoginInput, PublicUser, RegistrationError, RegistrationInput, validate_login,
        validate_registration,
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
    Database(#[from] sqlx::Error),
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
            email: user.email,
            display_name: user.display_name,
            status: "active".to_owned(),
            created_at: user.created_at,
        })
    }

    pub async fn authenticate(&self, input: LoginInput) -> Result<uuid::Uuid, UserServiceError> {
        let login = validate_login(input).map_err(|error| match error {
            LoginError::InvalidEmail | LoginError::EmptyPassword => {
                UserServiceError::InvalidCredentials
            }
        })?;
        let Some(credentials) =
            repository::find_credentials_by_email(&self.pool, &login.email).await?
        else {
            return Err(UserServiceError::InvalidCredentials);
        };
        if credentials.status != "active"
            || !verify_password(&login.password, &credentials.password_hash)
        {
            return Err(UserServiceError::InvalidCredentials);
        }

        Ok(credentials.id)
    }

    pub async fn find_profile(
        &self,
        id: uuid::Uuid,
    ) -> Result<Option<repository::UserProfile>, UserServiceError> {
        Ok(repository::find_profile_by_id(&self.pool, id).await?)
    }
}
