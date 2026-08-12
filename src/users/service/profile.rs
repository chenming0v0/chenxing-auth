//! 本人资料读取、显示名更新与改密。

use super::{UserService, UserServiceError};
use crate::{
    auth_limiter::{
        FailureDimension, LimiterDimension, MissingSourceIpPolicy, domain::commit_reserved_failure,
    },
    users::{
        credentials::{hash_password, verify_password},
        domain::{UserId, UserStatus, validate_display_name, validate_password_length},
        repository,
    },
};

impl UserService {
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

    /// 修改口令。
    ///
    /// 长度校验走与注册同一个 `validate_password_length`，上下界不允许在两条路径
    /// 之间漂移（Issue #122）。校验通过后由仓储层在同一事务内改哈希并撤销全部会话。
    pub async fn change_password(
        &self,
        id: UserId,
        current_password: &str,
        new_password: &str,
        source_ip: Option<&str>,
    ) -> Result<(), UserServiceError> {
        validate_password_length(new_password).map_err(UserServiceError::Validation)?;
        let Some(credentials) = repository::find_credentials_by_id(&self.pool, id).await? else {
            return Err(UserServiceError::InvalidCredentials);
        };

        // 与登录同一个账号维度键：匹配值，不是展示值（Issue #302）。
        let dimensions =
            self.password_change_dimensions(&credentials.canonical_email, source_ip)?;
        if !self.limiter.reserve(dimensions.clone()).await? {
            return Err(UserServiceError::RateLimited);
        }

        if UserStatus::parse(&credentials.status) != Some(UserStatus::Active) {
            self.limiter.release(dimensions).await?;
            return Err(UserServiceError::InvalidCredentials);
        }

        if !verify_password(
            current_password.to_owned(),
            credentials.password_hash.clone(),
        )
        .await
        {
            return self.record_password_failure(dimensions).await;
        }

        // Current-password authentication succeeded. The hash and transaction below are
        // non-authentication failures, so return the reservation before doing either.
        self.limiter.release(dimensions).await?;

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
        dimensions: Vec<LimiterDimension>,
    ) -> Result<(), UserServiceError> {
        let record = commit_reserved_failure(self.limiter.as_ref(), dimensions).await?;
        if record.reached.is_empty() {
            Err(UserServiceError::InvalidCredentials)
        } else {
            Err(UserServiceError::RateLimited)
        }
    }
}
