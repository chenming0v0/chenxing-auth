//! 登录校验与失败限流协作。
//!
//! 限流维度的预留、释放与失败记账都在这里：认证是唯一需要"先预留再按结果
//! 回滚或记账"的用例，把这套协作和登录判定放在一起，避免它散到其他用例里。
//!
//! 计时约束：进入有效登录认证流程后，所有最终认证失败或限流结果都必须完成一次
//! Argon2；已经做过真实口令校验的失败复用那次校验，尚未校验的路径使用哑校验填充。

use super::{UserService, UserServiceError};
use crate::{
    auth_limiter::{
        AuthReservation, FailureDimension, LimiterDimension, MissingSourceIpPolicy,
        domain::commit_reserved_failure,
    },
    users::{
        credentials::verify_login_password,
        domain::{AuthenticatedUser, LoginError, LoginInput, UserStatus, validate_login},
        repository,
    },
};

enum AuthenticationFailure {
    RateLimited,
    RecordFailure(AuthReservation),
}

/// 保证一次登录尝试最多只消耗一次 Argon2 校验。
///
/// 预留限流在口令校验之前命中时，`fill_if_unverified` 使用哑哈希补齐计时；
/// 已经校验过真实口令时则不再重复计算。
struct LoginPassword {
    value: Option<String>,
}
impl LoginPassword {
    fn new(value: String) -> Self {
        Self { value: Some(value) }
    }

    async fn verify_against(&mut self, password_hash: String) -> bool {
        let Some(value) = self.value.take() else {
            return false;
        };
        verify_login_password(value, Some(password_hash)).await
    }

    async fn fill_if_unverified(&mut self) {
        if let Some(value) = self.value.take() {
            let _ = verify_login_password(value, None).await;
        }
    }
}

impl UserService {
    /// 校验第一因子口令，返回绑定了凭据版本的认证身份。
    ///
    /// 返回 [`AuthenticatedUser`] 而不是裸 `UserId`（Issue #274）：`session_epoch`
    /// 与 `password_hash` 来自同一次行读取，调用方据此在签发 login ticket 或
    /// Session 时原子确认"这次口令校验所依据的版本还没被改密推进"。
    pub async fn authenticate(
        &self,
        input: LoginInput,
        source_ip: Option<&str>,
    ) -> Result<AuthenticatedUser, UserServiceError> {
        // 结构化校验先于限流预留与数据库查询：超长口令和超长标识符必须在触达
        // Argon2、SQL 和限流维度之前被拒绝（Issue #259）。三类校验失败归一为同一个
        // `InvalidLoginInput`，处理器再把它映射成与"凭据错误"完全一致的 401，
        // 因此拒绝行为不引入新的账号存在性信号。
        let login = validate_login(input).map_err(|error| match error {
            LoginError::InvalidIdentifier
            | LoginError::EmptyPassword
            | LoginError::PasswordTooLong => UserServiceError::InvalidLoginInput,
        })?;
        let mut password = LoginPassword::new(login.password);
        let source_ip = self.source_ip(source_ip)?;
        let source_dimensions = source_ip
            .as_deref()
            .map(|source_ip| vec![(FailureDimension::SourceIp, source_ip.to_owned())])
            .unwrap_or_default();
        let source_reservation = self.reserve_dimensions(source_dimensions.clone()).await?;
        if source_reservation.is_denied() {
            return self
                .finish_authentication_failure(&mut password, AuthenticationFailure::RateLimited)
                .await;
        }
        let credentials =
            match repository::find_credentials_by_identifier(&self.pool, &login.identifier).await {
                Ok(credentials) => credentials,
                Err(error) => {
                    self.release_dimensions(source_reservation).await?;
                    return Err(UserServiceError::Database(error));
                }
            };
        let Some(credentials) = credentials else {
            return self
                .finish_authentication_failure(
                    &mut password,
                    AuthenticationFailure::RecordFailure(source_reservation),
                )
                .await;
        };
        // 账号维度用匹配值而不是展示值（Issue #302）：同一账号的多种邮箱书写
        // （大小写、Unicode/Punycode 等价形态）规范化到同一个 `canonical_email`，
        // 按展示值分桶会让攻击者变换书写就换到一个新的失败计数桶。
        let account_key = credentials.canonical_email.clone();
        let account_dimensions = vec![(FailureDimension::Account, account_key)];
        let account_reservation = match self.reserve_dimensions(account_dimensions.clone()).await {
            Ok(reserved) => reserved,
            Err(error) => {
                // 账户预留失败不会替 source 预留做回滚，先尽力归还再传播原错误。
                let dimension_count = source_dimensions.len();
                if let Err(release_error) =
                    self.release_dimensions(source_reservation.clone()).await
                {
                    tracing::error!(
                        event = "auth_limiter.reservation_release_failed",
                        operation = "authentication_account_reserve",
                        dimensions = dimension_count,
                        error = %release_error,
                        "reserved source authentication quota was not released after account reservation failure"
                    );
                }
                return Err(error);
            }
        };
        if account_reservation.is_denied() {
            self.release_dimensions(source_reservation).await?;
            return self
                .finish_authentication_failure(&mut password, AuthenticationFailure::RateLimited)
                .await;
        }
        let reservation = source_reservation.merge(account_reservation);
        // 认证身份在消费 password_hash 之前取出：两个值来自同一行，绑定关系
        // 由 `find_credentials_by_identifier` 的单条 SELECT 保证。
        let authenticated = credentials.authenticated();
        let password_valid = password.verify_against(credentials.password_hash).await;
        // 状态、口令登录开关与口令校验合并判定：三者中任何一项不通过都返回同一个
        // 错误，不让调用方区分"账号被禁用"和"口令错误"。
        if UserStatus::parse(&credentials.status) != Some(UserStatus::Active)
            || !credentials.password_login_enabled
            || !password_valid
        {
            return self
                .finish_authentication_failure(
                    &mut password,
                    AuthenticationFailure::RecordFailure(reservation),
                )
                .await;
        }

        self.release_dimensions(reservation).await?;
        Ok(authenticated)
    }

    /// 按 `missing_source_ip_policy` 处理缺失的源 IP。
    ///
    /// 登录与公开注册共用：Skip 记日志并继续（注册侧没有 IP 则不占配额维度），
    /// Reject 直接失败。
    pub(super) fn source_ip(
        &self,
        source_ip: Option<&str>,
    ) -> Result<Option<String>, UserServiceError> {
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
    ) -> Result<AuthReservation, UserServiceError> {
        Ok(self.limiter.reserve(dimensions).await?)
    }

    async fn release_dimensions(
        &self,
        reservation: AuthReservation,
    ) -> Result<(), UserServiceError> {
        Ok(self.limiter.release(reservation).await?)
    }

    async fn record_failure(
        &self,
        reservation: AuthReservation,
    ) -> Result<crate::auth_limiter::domain::FailureRecord, UserServiceError> {
        Ok(commit_reserved_failure(self.limiter.as_ref(), reservation).await?)
    }

    async fn finish_authentication_failure(
        &self,
        password: &mut LoginPassword,
        failure: AuthenticationFailure,
    ) -> Result<AuthenticatedUser, UserServiceError> {
        password.fill_if_unverified().await;
        let error = match failure {
            AuthenticationFailure::RateLimited => UserServiceError::RateLimited,
            AuthenticationFailure::RecordFailure(reservation) => {
                if self.record_failure(reservation).await?.reached.is_empty() {
                    UserServiceError::InvalidCredentials
                } else {
                    UserServiceError::RateLimited
                }
            }
        };
        Err(error)
    }
}

#[cfg(test)]
#[path = "authentication_tests.rs"]
mod tests;
