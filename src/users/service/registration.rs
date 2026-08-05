//! 注册、Owner 引导与特权用户创建。
//!
//! 三条路径共享同一组前置动作：校验输入、把明文口令 move 进哈希任务、
//! 再交给仓储层的 Owner 前提事务。差异只在仓储调用与返回语义。

use super::{BootstrapOwnerResult, UserService, UserServiceError};
use crate::users::{
    credentials::hash_password,
    domain::{PublicUser, RegistrationInput, UserId, UserRole, validate_registration},
    repository,
};

impl UserService {
    pub async fn register(&self, input: RegistrationInput) -> Result<PublicUser, UserServiceError> {
        let mut registration = validate_registration(input)?;
        self.ensure_email_policy_allows(&registration.email).await?;
        // 明文按值 move 进哈希任务：take 之后结构体里只剩空串，明文不会随
        // registration 继续流向仓储层。
        let password = std::mem::take(&mut registration.password);
        let password_hash = hash_password(password)
            .await
            .map_err(|_| UserServiceError::PasswordHash)?;
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
            role: UserRole::User,
            created_at: user.created_at,
        })
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

    pub async fn create_privileged(
        &self,
        input: RegistrationInput,
        role: UserRole,
    ) -> Result<UserId, UserServiceError> {
        let mut registration = validate_registration(input)?;
        let password = std::mem::take(&mut registration.password);
        let password_hash = hash_password(password)
            .await
            .map_err(|_| UserServiceError::PasswordHash)?;
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

    pub(super) async fn ensure_email_policy_allows(
        &self,
        email: &str,
    ) -> Result<(), UserServiceError> {
        crate::users::email_policy::ensure_email_policy_allows(&self.pool, email).await
    }
}
