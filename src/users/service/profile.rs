//! 本人资料读取、显示名更新与改密。

use super::{UserService, UserServiceError};
use crate::{
    auth_limiter::{
        FailureDimension, LimiterDimension, MissingSourceIpPolicy, domain::commit_reserved_failure,
    },
    users::{
        credentials::{hash_password, verify_password},
        domain::{
            UserId, UserStatus, validate_authentication_password, validate_display_name,
            validate_password_length,
        },
        repository,
    },
};

impl UserService {
    pub async fn reauthenticate_password(
        &self,
        id: UserId,
        password: &str,
        source_ip: Option<&str>,
    ) -> Result<Option<crate::users::domain::AuthenticatedUser>, UserServiceError> {
        validate_authentication_password(password)
            .map_err(|_| UserServiceError::InvalidCredentials)?;
        let Some(credentials) = repository::find_credentials_by_id(&self.pool, id).await? else {
            return Err(UserServiceError::InvalidCredentials);
        };
        if !credentials.password_login_enabled {
            return Ok(None);
        }
        let dimensions =
            self.password_change_dimensions(&credentials.canonical_email, source_ip)?;
        let reservation = self.limiter.reserve(dimensions.clone()).await?;
        if reservation.is_denied() {
            return Err(UserServiceError::RateLimited);
        }
        if UserStatus::parse(&credentials.status) != Some(UserStatus::Active)
            || !verify_password(password.to_owned(), credentials.password_hash.clone()).await
        {
            return match self.record_password_failure(reservation).await {
                Ok(()) => Err(UserServiceError::InvalidCredentials),
                Err(error) => Err(error),
            };
        }
        self.limiter.release(reservation).await?;
        Ok(Some(credentials.authenticated()))
    }

    pub async fn find_profile(
        &self,
        id: UserId,
    ) -> Result<Option<repository::UserProfile>, UserServiceError> {
        Ok(repository::find_profile_by_id(&self.pool, id).await?)
    }

    /// 读取 active 用户的当前 `session_epoch`（Issue #409）。
    ///
    /// Refresh Token 签发与兑换用它做凭据代际比对：token 内 stamp 的 epoch 与
    /// 当前值不一致，说明期间发生过撤销该用户全部凭据的操作（改密、管理端
    /// TOTP 重置、禁用）。`None` 表示用户不存在或不是 active 状态。
    pub async fn active_session_epoch(&self, id: UserId) -> Result<Option<i64>, UserServiceError> {
        Ok(repository::find_active_session_epoch(&self.pool, id).await?)
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

    pub async fn update_profile(
        &self,
        id: UserId,
        display_name: Option<String>,
        username: Option<String>,
        current_password: Option<&str>,
        source_ip: Option<&str>,
    ) -> Result<super::ProfileUpdateOutcome, UserServiceError> {
        let display_name = validate_display_name(display_name)?;
        let Some(current_profile) = repository::find_profile_by_id(&self.pool, id).await? else {
            return Ok(super::ProfileUpdateOutcome::UserMissing);
        };
        let normalized_username =
            normalized_username_change(&current_profile.username, username.as_deref())?;
        let username_changed = normalized_username.is_some();

        if !username_changed {
            if !repository::update_display_name(&self.pool, id, display_name.as_deref()).await? {
                return Ok(super::ProfileUpdateOutcome::UserMissing);
            }
            return Ok(repository::find_profile_by_id(&self.pool, id)
                .await?
                .map(|profile| super::ProfileUpdateOutcome::Updated {
                    profile,
                    username_changed: false,
                })
                .unwrap_or(super::ProfileUpdateOutcome::UserMissing));
        }

        let Some(current_password) = current_password else {
            return Err(UserServiceError::CurrentPasswordRequired);
        };
        let authenticated = self
            .reauthenticate_password(id, current_password, source_ip)
            .await?;
        let Some(authenticated) = authenticated else {
            return Err(UserServiceError::PasswordReauthenticationUnavailable);
        };
        match repository::update_profile_with_epoch(
            &self.pool,
            id,
            normalized_username.as_deref().expect("changed username"),
            display_name.as_deref(),
            authenticated.session_epoch,
        )
        .await
        {
            Ok(repository::ProfileUpdateRepositoryOutcome::Updated(profile)) => {
                Ok(super::ProfileUpdateOutcome::Updated {
                    profile,
                    username_changed: true,
                })
            }
            Ok(repository::ProfileUpdateRepositoryOutcome::AuthenticationChanged) => {
                Ok(super::ProfileUpdateOutcome::AuthenticationChanged)
            }
            Ok(repository::ProfileUpdateRepositoryOutcome::UserMissing) => {
                Ok(super::ProfileUpdateOutcome::UserMissing)
            }
            Err(error)
                if error
                    .as_database_error()
                    .and_then(|database_error| database_error.constraint())
                    .is_some_and(|constraint| constraint == "users_username_key") =>
            {
                Ok(super::ProfileUpdateOutcome::UsernameUnavailable)
            }
            Err(error) => Err(UserServiceError::Database(error)),
        }
    }

    /// 修改口令。
    ///
    /// 新口令走与注册同一个 `validate_password_length`，上下界不允许漂移（Issue #122）。
    /// 当前口令走与登录同一个 [`validate_authentication_password`]：空或超长在查库、
    /// 限流预留和 Argon2 之前拒绝，并归一为 [`UserServiceError::InvalidCredentials`]，
    /// 避免长度成为可区分的 oracle（Issue #462）。
    pub async fn change_password(
        &self,
        id: UserId,
        current_password: &str,
        new_password: &str,
        source_ip: Option<&str>,
    ) -> Result<(), UserServiceError> {
        validate_password_length(new_password).map_err(UserServiceError::Validation)?;
        // 空/超长当前口令与口令错误对外同一条错误：长度不能成为 oracle。
        validate_authentication_password(current_password)
            .map_err(|_| UserServiceError::InvalidCredentials)?;
        let Some(credentials) = repository::find_credentials_by_id(&self.pool, id).await? else {
            return Err(UserServiceError::InvalidCredentials);
        };

        // 与登录同一个账号维度键：匹配值，不是展示值（Issue #302）。
        let dimensions =
            self.password_change_dimensions(&credentials.canonical_email, source_ip)?;
        let reservation = self.limiter.reserve(dimensions.clone()).await?;
        if reservation.is_denied() {
            return Err(UserServiceError::RateLimited);
        }

        if UserStatus::parse(&credentials.status) != Some(UserStatus::Active) {
            self.limiter.release(reservation).await?;
            return Err(UserServiceError::InvalidCredentials);
        }

        if !verify_password(
            current_password.to_owned(),
            credentials.password_hash.clone(),
        )
        .await
        {
            return self.record_password_failure(reservation).await;
        }

        // Current-password authentication succeeded. The hash and transaction below are
        // non-authentication failures, so return the reservation before doing either.
        self.limiter.release(reservation).await?;

        // 认证 epoch 与被校验的 `password_hash` 同一次读取（Issue #274）：写入事务
        // 内再比对一次，并发改密的败者不会用已作废的当前口令改出新口令。
        let authenticated = credentials.authenticated();
        let password_hash = hash_password(new_password.to_owned())
            .await
            .map_err(|_| UserServiceError::PasswordHash)?;
        match repository::change_password_and_revoke_all(
            &self.pool,
            id,
            &password_hash,
            authenticated.session_epoch,
        )
        .await?
        {
            repository::PasswordChangeOutcome::Changed => Ok(()),
            // 两种失败对调用方是同一件事："你提供的当前口令不再有效"。
            repository::PasswordChangeOutcome::UserMissing
            | repository::PasswordChangeOutcome::EpochChanged => {
                Err(UserServiceError::InvalidCredentials)
            }
        }
    }

    fn password_change_dimensions(
        &self,
        account_key: &str,
        source_ip: Option<&str>,
    ) -> Result<Vec<LimiterDimension>, UserServiceError> {
        let mut dimensions = vec![(FailureDimension::Account, account_key.to_owned())];
        match (source_ip, self.missing_source_ip_policy) {
            (Some(source_ip), _) => {
                dimensions.push((FailureDimension::SourceIp, source_ip.to_owned()))
            }
            (None, MissingSourceIpPolicy::Skip) => tracing::warn!(
                event = "auth_limiter.source_ip_unavailable",
                policy = MissingSourceIpPolicy::Skip.as_str(),
                "password change is using account-only limiting"
            ),
            (None, MissingSourceIpPolicy::Reject) => {
                tracing::error!(
                    event = "auth_limiter.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Reject.as_str(),
                    "password change rejected without trusted ConnectInfo"
                );
                return Err(UserServiceError::SourceIpUnavailable);
            }
        }
        Ok(dimensions)
    }

    async fn record_password_failure(
        &self,
        reservation: crate::auth_limiter::AuthReservation,
    ) -> Result<(), UserServiceError> {
        let record = commit_reserved_failure(self.limiter.as_ref(), reservation).await?;
        if record.reached.is_empty() {
            Err(UserServiceError::InvalidCredentials)
        } else {
            Err(UserServiceError::RateLimited)
        }
    }
}

fn normalized_username_change(
    current_username: &str,
    requested_username: Option<&str>,
) -> Result<Option<String>, crate::users::domain::RegistrationError> {
    let Some(requested_username) = requested_username else {
        return Ok(None);
    };
    let normalized = crate::users::domain::validate_username(requested_username)
        .ok_or(crate::users::domain::RegistrationError::InvalidUsername)?;
    Ok((normalized != current_username).then_some(normalized))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::UserService;
    use crate::auth_limiter::{AuthFailureLimiter, FailureDimension, domain::LimiterFuture};
    use crate::users::credentials::MAX_PASSWORD_LENGTH;
    use crate::users::domain::RegistrationError;
    use crate::users::service::UserServiceError;

    #[derive(Default)]
    struct CountingLimiter {
        calls: AtomicUsize,
    }

    impl CountingLimiter {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl AuthFailureLimiter for CountingLimiter {
        fn is_limited<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &str,
        ) -> LimiterFuture<'a, bool> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(false) })
        }

        fn record_failure<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &str,
        ) -> LimiterFuture<'a, bool> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(false) })
        }

        fn clear<'a>(
            &'a self,
            _dimension: FailureDimension,
            _value: &str,
        ) -> LimiterFuture<'a, ()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    fn service(limiter: Arc<CountingLimiter>) -> UserService {
        let pool = crate::sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid-host/unused")
            .expect("lazy pool");
        UserService::new(pool, limiter)
    }

    #[test]
    fn username_normalization_distinguishes_real_changes() {
        assert_eq!(
            super::normalized_username_change("chenxing", Some(" ChenXing ")),
            Ok(None)
        );
        assert_eq!(
            super::normalized_username_change("chenxing", Some("renamed-user")),
            Ok(Some("renamed-user".to_owned()))
        );
        assert_eq!(
            super::normalized_username_change("chenxing", Some("admin")),
            Err(RegistrationError::InvalidUsername)
        );
    }

    /// Issue #462：超长当前口令必须在查库、限流预留和 Argon2 之前被拒绝。
    ///
    /// `limiter.calls() == 0` 证明没触达限流；结果是 `InvalidCredentials` 而不是
    /// `Database` 证明没查库（连接池指向不可用主机）。Argon2 在这两步之后。
    #[tokio::test]
    async fn oversized_current_password_is_rejected_before_lookup_or_limiter() {
        let limiter = Arc::new(CountingLimiter::default());
        let result = service(limiter.clone())
            .change_password(
                1,
                &"a".repeat(MAX_PASSWORD_LENGTH + 1),
                "replacement-password",
                Some("127.0.0.1"),
            )
            .await;

        assert!(matches!(result, Err(UserServiceError::InvalidCredentials)));
        assert_eq!(limiter.calls(), 0);
    }

    #[tokio::test]
    async fn empty_current_password_is_rejected_before_lookup_or_limiter() {
        let limiter = Arc::new(CountingLimiter::default());
        let result = service(limiter.clone())
            .change_password(1, "", "replacement-password", Some("127.0.0.1"))
            .await;

        assert!(matches!(result, Err(UserServiceError::InvalidCredentials)));
        assert_eq!(limiter.calls(), 0);
    }

    /// 存量短口令不能被改密路径用注册下界挡掉，否则会锁死旧账号。
    #[tokio::test]
    async fn short_current_password_still_reaches_database() {
        let limiter = Arc::new(CountingLimiter::default());
        let result = service(limiter.clone())
            .change_password(1, "short", "replacement-password", Some("127.0.0.1"))
            .await;

        assert!(matches!(result, Err(UserServiceError::Database(_))));
        assert_eq!(limiter.calls(), 0);
    }

    #[tokio::test]
    async fn new_password_policy_is_checked_before_current_password() {
        let limiter = Arc::new(CountingLimiter::default());
        let result = service(limiter.clone())
            .change_password(
                1,
                &"a".repeat(MAX_PASSWORD_LENGTH + 1),
                "too-short",
                Some("127.0.0.1"),
            )
            .await;

        assert!(matches!(
            result,
            Err(UserServiceError::Validation(
                RegistrationError::PasswordTooShort
            ))
        ));
        assert_eq!(limiter.calls(), 0);
    }
}
