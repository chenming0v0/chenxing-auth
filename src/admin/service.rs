use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use thiserror::Error;

use super::{
    domain::{AdminId, AdminRole},
    repository,
};
use crate::users::credentials::verify_password;

#[derive(Clone)]
pub struct AdminService {
    pool: crate::sqlx::PgPool,
}

#[derive(Debug, Error)]
pub enum AdminServiceError {
    #[error("admin username is invalid")]
    InvalidUsername,
    #[error("admin password is too short")]
    PasswordTooShort,
    #[error("admin role is invalid")]
    InvalidRole,
    #[error("admin credentials are invalid")]
    InvalidCredentials,
    #[error("password hashing failed")]
    PasswordHash,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

impl AdminService {
    pub fn new(pool: crate::sqlx::PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        username: &str,
        password: &str,
        role: AdminRole,
    ) -> Result<AdminId, AdminServiceError> {
        let username = normalize_username(username)?;
        if password.chars().count() < crate::users::domain::MIN_PASSWORD_LENGTH {
            return Err(AdminServiceError::PasswordTooShort);
        }
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AdminServiceError::PasswordHash)?
            .to_string();
        Ok(repository::insert(&self.pool, &username, &hash, role.as_str()).await?)
    }

    pub async fn bootstrap(
        &self,
        username: &str,
        password: &str,
        role: AdminRole,
    ) -> Result<Option<AdminId>, AdminServiceError> {
        let username = normalize_username(username)?;
        if password.chars().count() < crate::users::domain::MIN_PASSWORD_LENGTH {
            return Err(AdminServiceError::PasswordTooShort);
        }
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AdminServiceError::PasswordHash)?
            .to_string();
        Ok(repository::insert_bootstrap(&self.pool, &username, &hash, role.as_str()).await?)
    }

    pub async fn is_initialized(&self) -> Result<bool, AdminServiceError> {
        Ok(repository::is_initialized(&self.pool).await?)
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(AdminId, AdminRole), AdminServiceError> {
        let username = normalize_username(username)?;
        let Some(admin) = repository::find_by_username(&self.pool, &username).await? else {
            return Err(AdminServiceError::InvalidCredentials);
        };
        let Some(role) = AdminRole::parse(&admin.role) else {
            return Err(AdminServiceError::InvalidCredentials);
        };
        if admin.status != "active" || !verify_password(password, &admin.password_hash) {
            return Err(AdminServiceError::InvalidCredentials);
        }
        repository::touch_login(&self.pool, admin.id).await?;
        Ok((admin.id, role))
    }

    pub async fn find(
        &self,
        id: AdminId,
    ) -> Result<Option<(AdminId, String, AdminRole, String)>, AdminServiceError> {
        Ok(repository::find_by_id(&self.pool, id)
            .await?
            .and_then(|admin| {
                AdminRole::parse(&admin.role)
                    .map(|role| (admin.id, admin.username, role, admin.status))
            }))
    }

    pub async fn list(
        &self,
    ) -> Result<Vec<(AdminId, String, AdminRole, String)>, AdminServiceError> {
        Ok(repository::list(&self.pool)
            .await?
            .into_iter()
            .filter_map(|admin| {
                AdminRole::parse(&admin.role)
                    .map(|role| (admin.id, admin.username, role, admin.status))
            })
            .collect())
    }

    pub async fn set_status(&self, id: AdminId, status: &str) -> Result<bool, AdminServiceError> {
        if !matches!(status, "active" | "disabled") {
            return Ok(false);
        }
        Ok(repository::set_status(&self.pool, id, status).await?)
    }
}

fn normalize_username(value: &str) -> Result<String, AdminServiceError> {
    let username = value.trim().to_owned();
    let length = username.chars().count();
    if !(3..=64).contains(&length) || username.chars().any(char::is_whitespace) {
        return Err(AdminServiceError::InvalidUsername);
    }
    Ok(username)
}
