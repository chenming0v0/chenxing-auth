//! 注册、Owner 引导与管理侧用户创建。
//!
//! 管理侧创建和 Owner 引导共享校验、口令哈希和仓储事务边界；公开注册则在
//! 邮件所有权验证能力接入前 fail-closed，不创建未验证身份。

use super::{BootstrapOwnerResult, UserService, UserServiceError};
use crate::{
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
        _source_ip: Option<&str>,
    ) -> Result<PublicUser, UserServiceError> {
        // A valid input is not enough to create an active account. The current
        // repository has SMTP settings, but no delivery adapter or verification
        // token consumer, so accepting this request would create an account whose
        // email ownership cannot be proved. Fail closed without hashing or writing
        // any identity data; a future real verifier can replace this boundary with
        // an expiring, atomically reserved pending-registration flow.
        validate_registration(input)?;
        Err(UserServiceError::EmailVerificationUnavailable)
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
