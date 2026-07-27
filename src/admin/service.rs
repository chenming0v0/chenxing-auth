use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use thiserror::Error;
use uuid::Uuid;

use super::{domain::AdminRole, repository};
use crate::users::credentials::verify_password;

#[derive(Clone)]
pub struct AdminService {
    pool: sqlx::PgPool,
}

#[derive(Debug, Error)]
pub enum AdminServiceError {
    #[error("admin email is invalid")]
    InvalidEmail,
    #[error("admin password is too short")]
    PasswordTooShort,
    #[error("admin role is invalid")]
    InvalidRole,
    #[error("admin credentials are invalid")]
    InvalidCredentials,
    #[error("password hashing failed")]
    PasswordHash,
    #[error("database operation failed: {0}")]
    Database(#[from] sqlx::Error),
}

impl AdminService {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        email: &str,
        password: &str,
        role: AdminRole,
    ) -> Result<Uuid, AdminServiceError> {
        let email = normalize_email(email)?;
        if password.chars().count() < 12 {
            return Err(AdminServiceError::PasswordTooShort);
        }
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AdminServiceError::PasswordHash)?
            .to_string();
        Ok(repository::insert(&self.pool, &email, &hash, role.as_str()).await?)
    }

    pub async fn bootstrap(
        &self,
        email: &str,
        password: &str,
        role: AdminRole,
    ) -> Result<Option<Uuid>, AdminServiceError> {
        let email = normalize_email(email)?;
        if password.chars().count() < 12 {
            return Err(AdminServiceError::PasswordTooShort);
        }
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AdminServiceError::PasswordHash)?
            .to_string();
        Ok(repository::insert_bootstrap(&self.pool, &email, &hash, role.as_str()).await?)
    }

    pub async fn authenticate(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(Uuid, AdminRole), AdminServiceError> {
        let email = normalize_email(email)?;
        let Some(admin) = repository::find_by_email(&self.pool, &email).await? else {
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
        id: Uuid,
    ) -> Result<Option<(Uuid, String, AdminRole, String)>, AdminServiceError> {
        Ok(repository::find_by_id(&self.pool, id)
            .await?
            .and_then(|admin| {
                AdminRole::parse(&admin.role)
                    .map(|role| (admin.id, admin.email, role, admin.status))
            }))
    }

    pub async fn list(&self) -> Result<Vec<(Uuid, String, AdminRole, String)>, AdminServiceError> {
        Ok(repository::list(&self.pool)
            .await?
            .into_iter()
            .filter_map(|admin| {
                AdminRole::parse(&admin.role)
                    .map(|role| (admin.id, admin.email, role, admin.status))
            })
            .collect())
    }

    pub async fn set_status(&self, id: Uuid, status: &str) -> Result<bool, AdminServiceError> {
        if !matches!(status, "active" | "disabled") {
            return Ok(false);
        }
        Ok(repository::set_status(&self.pool, id, status).await?)
    }
}

fn normalize_email(value: &str) -> Result<String, AdminServiceError> {
    let email = value.trim().to_ascii_lowercase();
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if parts.next().is_some() || local.is_empty() || !domain.contains('.') {
        return Err(AdminServiceError::InvalidEmail);
    }
    Ok(email)
}
