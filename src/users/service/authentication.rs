//! 登录校验与失败限流协作。
//!
//! 限流维度的预留、释放与失败记账都在这里：认证是唯一需要"先预留再按结果
//! 回滚或记账"的用例，把这套协作和登录判定放在一起，避免它散到其他用例里。
//!
//! 计时约束：无论标识符是否命中用户，都必须执行一次完整的 Argon2。
//! `verify_login_password(_, None)` 负责"用户不存在"路径的计时填充（Issue #124）。

use super::{UserService, UserServiceError};
use crate::{
    auth_limiter::{FailureDimension, LimiterDimension, MissingSourceIpPolicy},
    users::{
        credentials::verify_login_password,
        domain::{LoginError, LoginInput, UserId, validate_login},
        repository,
    },
};

impl UserService {
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
        let source_dimensions = source_ip
            .as_deref()
            .map(|source_ip| vec![(FailureDimension::SourceIp, source_ip.to_owned())])
            .unwrap_or_default();
        if !self.reserve_dimensions(source_dimensions.clone()).await? {
            return Err(UserServiceError::RateLimited);
        }
        let credentials =
            match repository::find_credentials_by_identifier(&self.pool, &login.identifier).await {
                Ok(credentials) => credentials,
                Err(error) => {
                    self.release_dimensions(source_dimensions).await?;
                    return Err(UserServiceError::Database(error));
                }
            };
        let Some(credentials) = credentials else {
            // 计时填充：标识符没命中用户时仍然跑完一次 Argon2，否则"用户不存在"
            // 会比"口令错误"快约 50 ms 返回，可用于枚举已注册账号。
            let _ = verify_login_password(login.password.clone(), None).await;
            if self
                .record_failure(source_dimensions)
                .await?
                .reached
                .is_empty()
            {
                return Err(UserServiceError::InvalidCredentials);
            } else {
                return Err(UserServiceError::RateLimited);
            }
        };
        let account_key = credentials.email.clone();
        let account_dimensions = vec![(FailureDimension::Account, account_key)];
        if !self.reserve_dimensions(account_dimensions.clone()).await? {
            self.release_dimensions(source_dimensions).await?;
            return Err(UserServiceError::RateLimited);
        }
        let mut dimensions = source_dimensions;
        dimensions.extend(account_dimensions);
        let password_valid = verify_login_password(
            login.password.clone(),
            Some(credentials.password_hash.clone()),
        )
        .await;
        // 状态、口令登录开关与口令校验合并判定：三者中任何一项不通过都返回同一个
        // 错误，不让调用方区分"账号被禁用"和"口令错误"。
        if credentials.status != "active" || !credentials.password_login_enabled || !password_valid {
            if self.record_failure(dimensions).await?.reached.is_empty() {
                return Err(UserServiceError::InvalidCredentials);
            } else {
                return Err(UserServiceError::RateLimited);
            }
        }

        self.release_dimensions(dimensions).await?;
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

    async fn reserve_dimensions(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<bool, UserServiceError> {
        Ok(self.limiter.reserve(dimensions).await?)
    }

    async fn release_dimensions(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<(), UserServiceError> {
        Ok(self.limiter.release(dimensions).await?)
    }

    async fn record_failure(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<crate::auth_limiter::domain::FailureRecord, UserServiceError> {
        Ok(self.limiter.record_reserved_failures(dimensions).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicUsize};

    use super::{UserService, UserServiceError};
    use crate::auth_limiter::domain::LimiterFuture;
    use crate::auth_limiter::{AuthFailureLimiter, FailureDimension};
    use crate::users::domain::LoginInput;

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
