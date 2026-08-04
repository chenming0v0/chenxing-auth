use std::sync::Arc;

use thiserror::Error;

use super::{
    credentials::{hash_password, verify_password},
    domain::{
        LoginError, LoginInput, PublicUser, RegistrationError, RegistrationInput, UserId, UserRole,
        validate_display_name, validate_login, validate_registration,
    },
    query_repository, repository,
};
use crate::{
    auth_limiter::{AuthFailureLimiter, FailureDimension, LimiterDimension, MissingSourceIpPolicy},
    sqlx::PgPool,
};

#[derive(Clone)]
pub struct UserService {
    pool: PgPool,
    limiter: Arc<dyn AuthFailureLimiter>,
    missing_source_ip_policy: MissingSourceIpPolicy,
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
    #[error("login input format is invalid")]
    InvalidLoginInput,
    #[error("authentication rate limit reached")]
    RateLimited,
    #[error("authentication limiter failed: {0}")]
    Limiter(#[from] crate::auth_limiter::domain::AuthLimiterError),
    #[error("trusted source IP is unavailable")]
    SourceIpUnavailable,
    #[error("last active owner is required")]
    LastOwnerRequired,
    #[error("owner bootstrap is required before public registration")]
    OwnerBootstrapRequired,
    #[error("email domain is not allowed by policy")]
    EmailDomainNotAllowed,
}

impl UserService {
    pub fn new(pool: PgPool, limiter: Arc<dyn AuthFailureLimiter>) -> Self {
        Self::with_source_ip_policy(pool, limiter, MissingSourceIpPolicy::Skip)
    }

    pub fn with_source_ip_policy(
        pool: PgPool,
        limiter: Arc<dyn AuthFailureLimiter>,
        missing_source_ip_policy: MissingSourceIpPolicy,
    ) -> Self {
        Self {
            pool,
            limiter,
            missing_source_ip_policy,
        }
    }

    pub async fn register(&self, input: RegistrationInput) -> Result<PublicUser, UserServiceError> {
        let registration = validate_registration(input)?;
        self.ensure_email_policy_allows(&registration.email).await?;
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

    async fn ensure_email_policy_allows(&self, email: &str) -> Result<(), UserServiceError> {
        super::email_policy::ensure_email_policy_allows(&self.pool, email).await
    }

    pub async fn authenticate(
        &self,
        input: LoginInput,
        source_ip: Option<&str>,
    ) -> Result<UserId, UserServiceError> {
        let login = validate_login(input).map_err(|error| match error {
            LoginError::InvalidIdentifier | LoginError::EmptyPassword => {
                UserServiceError::InvalidLoginInput
            }
        })?;
        let source_ip = self.source_ip(source_ip)?;
        self.ensure_allowed(source_ip.as_deref()).await?;
        let Some(credentials) =
            repository::find_credentials_by_identifier(&self.pool, &login.identifier).await?
        else {
            if self.record_failure(None, source_ip.as_deref()).await? {
                return Err(UserServiceError::RateLimited);
            }
            return Err(UserServiceError::InvalidCredentials);
        };
        let account_key = credentials.id.to_string();
        self.ensure_account_allowed(&account_key).await?;
        if credentials.status != "active"
            || !credentials.password_login_enabled
            || !verify_password(&login.password, &credentials.password_hash)
        {
            if self
                .record_failure(Some(&account_key), source_ip.as_deref())
                .await?
            {
                return Err(UserServiceError::RateLimited);
            }
            return Err(UserServiceError::InvalidCredentials);
        }

        Ok(credentials.id)
    }

    fn source_ip(&self, source_ip: Option<&str>) -> Result<Option<String>, UserServiceError> {
        match (source_ip, self.missing_source_ip_policy) {
            (Some(source_ip), _) => Ok(Some(source_ip.to_owned())),
            (None, MissingSourceIpPolicy::Skip) => {
                tracing::warn!(
                    event = "auth_limiter.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Skip.as_str(),
                    "authentication attempt is using account-only limiting"
                );
                Ok(None)
            }
            (None, MissingSourceIpPolicy::Reject) => {
                tracing::error!(
                    event = "auth_limiter.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Reject.as_str(),
                    "authentication attempt rejected without trusted ConnectInfo"
                );
                Err(UserServiceError::SourceIpUnavailable)
            }
        }
    }

    async fn ensure_allowed(&self, source_ip: Option<&str>) -> Result<(), UserServiceError> {
        if let Some(source_ip) = source_ip {
            self.ensure_dimensions_allowed(vec![(
                FailureDimension::SourceIp,
                source_ip.to_owned(),
            )])
            .await?;
        }
        Ok(())
    }

    async fn ensure_account_allowed(&self, account_key: &str) -> Result<(), UserServiceError> {
        self.ensure_dimensions_allowed(vec![(FailureDimension::Account, account_key.to_owned())])
            .await
    }

    async fn ensure_dimensions_allowed(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<(), UserServiceError> {
        if self.limiter.any_limited(dimensions).await? {
            return Err(UserServiceError::RateLimited);
        }
        Ok(())
    }

    async fn record_failure(
        &self,
        account_key: Option<&str>,
        source_ip: Option<&str>,
    ) -> Result<bool, UserServiceError> {
        let mut dimensions = Vec::with_capacity(2);
        if let Some(account_key) = account_key {
            dimensions.push((FailureDimension::Account, account_key.to_owned()));
        }
        if let Some(source_ip) = source_ip {
            dimensions.push((FailureDimension::SourceIp, source_ip.to_owned()));
        }
        Ok(!self
            .limiter
            .record_failures(dimensions)
            .await?
            .reached
            .is_empty())
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
        if !repository::change_password_and_revoke_all(&self.pool, id, &password_hash).await? {
            return Err(UserServiceError::InvalidCredentials);
        }
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<repository::ListedUser>, UserServiceError> {
        Ok(repository::list_users(&self.pool).await?)
    }

    pub async fn query(
        &self,
        search: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<repository::ListedUser>, i64), UserServiceError> {
        Ok(query_repository::query_users(&self.pool, search, status, limit, offset).await?)
    }

    pub async fn counts(&self) -> Result<query_repository::UserCounts, UserServiceError> {
        Ok(query_repository::count_users(&self.pool).await?)
    }

    pub async fn list_administrators(
        &self,
    ) -> Result<Vec<repository::ListedUser>, UserServiceError> {
        Ok(query_repository::list_administrators(&self.pool).await?)
    }

    pub async fn set_status(&self, id: UserId, status: &str) -> Result<bool, UserServiceError> {
        self.set_status_guarded(id, status).await
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
    use std::sync::{Arc, atomic::AtomicUsize};

    use super::*;
    use crate::auth_limiter::domain::LimiterFuture;
    use crate::auth_limiter::{AuthFailureLimiter, FailureDimension};

    struct AlwaysLimited;

    #[derive(Default)]
    struct CountingLimiter {
        calls: AtomicUsize,
    }

    impl CountingLimiter {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl AuthFailureLimiter for CountingLimiter {
        fn is_limited<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &str,
        ) -> LimiterFuture<'a, bool> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async { Ok(false) })
        }

        fn record_failure<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &str,
        ) -> LimiterFuture<'a, bool> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async { Ok(false) })
        }

        fn clear<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &str,
        ) -> LimiterFuture<'a, ()> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    impl AuthFailureLimiter for AlwaysLimited {
        fn is_limited<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &str,
        ) -> LimiterFuture<'a, bool> {
            Box::pin(async { Ok(true) })
        }

        fn record_failure<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &str,
        ) -> LimiterFuture<'a, bool> {
            Box::pin(async { Ok(false) })
        }

        fn clear<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &str,
        ) -> LimiterFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn invalid_login_input_is_rejected_before_limiter_or_database() {
        let pool = crate::sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid-host/unused")
            .expect("lazy pool");
        let limiter = Arc::new(CountingLimiter::default());
        let service = UserService::new(pool, limiter.clone());
        let result = service
            .authenticate(
                LoginInput {
                    identifier: "ab".to_owned(),
                    password: "incorrect password".to_owned(),
                    totp_code: None,
                },
                Some("127.0.0.1"),
            )
            .await;

        assert!(matches!(result, Err(UserServiceError::InvalidLoginInput)));
        assert_eq!(limiter.calls(), 0);
    }

    #[tokio::test]
    async fn valid_login_input_still_uses_rate_limiter_before_database() {
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
                Some("127.0.0.1"),
            )
            .await;
        assert!(matches!(result, Err(UserServiceError::RateLimited)));
    }
}
