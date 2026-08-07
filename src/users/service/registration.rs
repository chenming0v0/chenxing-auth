//! 注册、Owner 引导与管理侧用户创建。
//!
//! 四条路径共享同一组前置动作：校验输入、把明文口令 move 进哈希任务、
//! 再交给仓储层的 Owner 前提事务。差异只在邮箱域名策略是否生效、
//! 落库的 (role, status) 以及返回语义。

use super::{BootstrapOwnerResult, UserService, UserServiceError};
use crate::{
    auth_limiter::{FailureDimension, LimiterDimension, MissingSourceIpPolicy},
    users::{
        credentials::hash_password,
        domain::{
            PublicUser, RegistrationInput, UserCreation, UserId, UserRole, UserStatus,
            validate_registration,
        },
        repository::{self, NewUser},
    },
};

impl UserService {
    pub async fn register(
        &self,
        input: RegistrationInput,
        source_ip: Option<&str>,
    ) -> Result<PublicUser, UserServiceError> {
        let registration = validate_registration(input)?;
        let dimensions = self.registration_dimensions(source_ip)?;
        // Reserve before policy/database work so Argon2 cannot be reached without admission.
        if !self.limiter.reserve(dimensions.clone()).await? {
            return Err(UserServiceError::RateLimited);
        }
        if let Err(error) = self.ensure_email_policy_allows(&registration.email).await {
            self.limiter.release(dimensions).await?;
            return Err(error);
        }
        let user = self
            .insert_after_owner(UserCreation {
                registration,
                role: UserRole::User,
                status: UserStatus::Active,
            })
            .await;
        match user {
            Ok(user) => {
                self.limiter.release(dimensions).await?;
                Ok(public_user(user))
            }
            Err(error) => {
                self.record_registration_failure(dimensions).await?;
                // Keep the original registration error. In particular, a unique
                // constraint must remain a 409 even when this failure reaches the
                // source-IP threshold; the next attempt is rejected by reserve().
                Err(error)
            }
        }
    }

    fn registration_dimensions(
        &self,
        source_ip: Option<&str>,
    ) -> Result<Vec<LimiterDimension>, UserServiceError> {
        match (source_ip, self.missing_source_ip_policy) {
            (Some(source_ip), _) => Ok(vec![(FailureDimension::SourceIp, source_ip.to_owned())]),
            (None, MissingSourceIpPolicy::Skip) => {
                tracing::warn!(
                    event = "auth_limiter.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Skip.as_str(),
                    "registration attempt is using no source-IP limiter dimension"
                );
                Ok(Vec::new())
            }
            (None, MissingSourceIpPolicy::Reject) => {
                tracing::error!(
                    event = "auth_limiter.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Reject.as_str(),
                    "registration attempt rejected without trusted ConnectInfo"
                );
                Err(UserServiceError::SourceIpUnavailable)
            }
        }
    }

    async fn record_registration_failure(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<(), UserServiceError> {
        match self
            .limiter
            .record_reserved_failures(dimensions.clone())
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => {
                if let Err(release_error) = self.limiter.release(dimensions).await {
                    tracing::error!(
                        event = "auth_limiter.reservation_release_failed",
                        operation = "registration_record_reserved_failures",
                        error = %release_error,
                        "reserved registration quota was not released after limiter failure"
                    );
                }
                Err(UserServiceError::Limiter(error))
            }
        }
    }

    /// 管理侧创建用户（Issue #133）。
    ///
    /// 与 `create_privileged` 的区别只有两点，且都是有意为之：
    /// - 这里执行邮箱域名策略。管理员通过后台批量建号时仍受同一份白名单约束，
    ///   否则策略只能拦住公开注册，等于给旁路留了一扇门。
    /// - 返回完整 `PublicUser`，让管理前端拿到落库后的 (role, status) 而不是回显请求体。
    pub async fn create_by_admin(
        &self,
        input: RegistrationInput,
        role: UserRole,
        status: UserStatus,
    ) -> Result<PublicUser, UserServiceError> {
        let registration = validate_registration(input)?;
        self.ensure_email_policy_allows(&registration.email).await?;
        let user = self
            .insert_after_owner(UserCreation {
                registration,
                role,
                status,
            })
            .await?;
        Ok(public_user(user))
    }

    pub async fn bootstrap_owner(
        &self,
        input: RegistrationInput,
    ) -> Result<BootstrapOwnerResult, UserServiceError> {
        let mut registration = validate_registration(input)?;
        let password = std::mem::take(&mut registration.password);
        let password_hash = hash_password(password)
            .await
            .map_err(|_| UserServiceError::PasswordHash)?;
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

    /// Owner 是否已初始化。
    ///
    /// SQL 收在 `repository::owner_exists`：服务层只表达用例，不内嵌裸 SQL（Issue #127）。
    pub async fn owner_initialized(&self) -> Result<bool, UserServiceError> {
        Ok(repository::owner_exists(&self.pool).await?)
    }

    /// `POST /api/v1/admin/admins` 的用例。
    ///
    /// 刻意不执行邮箱域名策略：这条路径创建的是管理员，调用方已经持有
    /// `ManageRoles`，域名白名单是面向注册用户的准入策略，不适用于此。
    pub async fn create_privileged(
        &self,
        input: RegistrationInput,
        role: UserRole,
    ) -> Result<UserId, UserServiceError> {
        let registration = validate_registration(input)?;
        let user = self
            .insert_after_owner(UserCreation {
                registration,
                role,
                status: UserStatus::Active,
            })
            .await?;
        Ok(user.id)
    }

    /// 哈希口令并在 Owner 前提下落库。
    ///
    /// 明文按值 move 进哈希任务：take 之后 `registration` 里只剩空串，
    /// 明文不会随 `UserCreation` 继续流向仓储层。
    async fn insert_after_owner(
        &self,
        mut creation: UserCreation,
    ) -> Result<NewUser, UserServiceError> {
        let password = std::mem::take(&mut creation.registration.password);
        let password_hash = hash_password(password)
            .await
            .map_err(|_| UserServiceError::PasswordHash)?;
        repository::insert_user_after_owner(&self.pool, creation, password_hash)
            .await?
            .ok_or(UserServiceError::OwnerBootstrapRequired)
    }

    pub(super) async fn ensure_email_policy_allows(
        &self,
        email: &str,
    ) -> Result<(), UserServiceError> {
        crate::users::email_policy::ensure_email_policy_allows(&self.pool, email).await
    }
}

/// 用落库结果构造对外视图。
///
/// (role, status) 取自 `NewUser` 而不是调用方的入参，响应因此必然与数据库一致。
/// `password_hash` 在此被丢弃，不进入任何响应。
fn public_user(user: NewUser) -> PublicUser {
    PublicUser {
        id: user.id,
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        status: user.status.as_str().to_owned(),
        role: user.role,
        created_at: user.created_at,
    }
}
