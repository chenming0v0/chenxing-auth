//! 注册、Owner 引导与管理侧用户创建。
//!
//! 管理侧创建和 Owner 引导共享校验、口令哈希和仓储事务边界；公开注册则在
//! 邮件所有权验证能力接入前 fail-closed，不创建未验证身份。

use super::{BootstrapOwnerResult, UserService, UserServiceError};
use crate::audit::AuditEvent;
use crate::users::{
    ManagementActorCredential,
    credentials::hash_password,
    domain::{
        PublicUser, RegistrationInput, UserCreation, UserId, UserPermission, UserRole, UserStatus,
        validate_registration,
    },
    email::EmailAddress,
    repository::{self, NewUser},
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
        actor_type: String,
        actor_id: Option<String>,
        actor_credential: ManagementActorCredential,
    ) -> Result<PublicUser, UserServiceError> {
        let registration = validate_registration(input)?;
        self.ensure_email_policy_allows(&registration.email).await?;
        let creation = UserCreation {
            registration,
            role,
            status,
        };
        let user = if role.is_privileged() {
            self.insert_after_owner_with_audit(
                creation,
                actor_type,
                actor_id,
                actor_credential,
                UserPermission::ManageRoles,
            )
            .await?
        } else {
            self.insert_after_owner(creation, actor_credential, UserPermission::ManageUsers)
                .await?
        };
        Ok(public_user(user))
    }

    /// 创建首个 Owner。
    ///
    /// 成功审计不是事后动作：事件由本用例构造，并由仓储层在引导事务内写入
    /// （Issue #304）。因此这里没有「创建成功但审计失败」的返回值 ——
    /// 审计失败会连带回滚用户创建，收敛成 [`UserServiceError::AuditUnavailable`]。
    ///
    /// `source_ip` 已由可信代理解析器取得，用于事后追溯「谁抢到了 Owner」。
    ///
    /// 已初始化判定必须在 Argon2 之前：哈希是 19 MiB 内存的计算成本，已初始化
    /// 实例上的每次探测都不该为一次注定被拒的请求付这笔账（Issue #346）。
    pub async fn bootstrap_owner(
        &self,
        input: RegistrationInput,
        source_ip: Option<&str>,
    ) -> Result<BootstrapOwnerResult, UserServiceError> {
        let mut registration = validate_registration(input)?;
        // 便宜判定先于慢哈希：限流只有 5 次/窗口/IP 的额度，`MissingSourceIpPolicy::Skip`
        // 部署下甚至为零，不能指望它兜底。这只是快速路径 —— 并发引导的权威判定仍在
        // 仓储事务的 advisory lock 内重新执行，预检放行不会制造「两个 Owner」的竞态窗口。
        if self.owner_initialized().await? {
            return Ok(BootstrapOwnerResult::AlreadyConfigured);
        }
        let password = std::mem::take(&mut registration.password);
        let password_hash = hash_password(password)
            .await
            .map_err(|_| UserServiceError::PasswordHash)?;
        let outcome = repository::bootstrap_owner(
            &self.pool,
            &registration.username,
            &registration.email,
            &password_hash,
            |profile| owner_bootstrap_audit_event(profile.id, source_ip),
        )
        .await
        .map_err(|error| match error {
            repository::BootstrapOwnerError::Database(error) => UserServiceError::Database(error),
            repository::BootstrapOwnerError::Audit(error) => {
                // 审计已经在 AuditService/仓储层留下结构化失败日志，这里只需要把
                // 「引导没有发生」这一事实原样上报，不把审计细节带进 HTTP 层。
                tracing::error!(
                    event = "owner_bootstrap.audit_unavailable",
                    error = %error,
                    "owner bootstrap was rolled back because its audit record could not be written"
                );
                UserServiceError::AuditUnavailable
            }
        })?;
        Ok(match outcome {
            repository::BootstrapOwnerOutcome::Created(profile) => {
                BootstrapOwnerResult::Created(profile)
            }
            repository::BootstrapOwnerOutcome::AlreadyConfigured => {
                BootstrapOwnerResult::AlreadyConfigured
            }
            repository::BootstrapOwnerOutcome::RequiresEmptyDatabase => {
                BootstrapOwnerResult::RequiresEmptyDatabase
            }
        })
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
        actor_type: String,
        actor_id: Option<String>,
        actor_credential: ManagementActorCredential,
    ) -> Result<UserId, UserServiceError> {
        let registration = validate_registration(input)?;
        let user = self
            .insert_after_owner_with_audit(
                UserCreation {
                    registration,
                    role,
                    status: UserStatus::Active,
                },
                actor_type,
                actor_id,
                actor_credential,
                UserPermission::ManageRoles,
            )
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
        actor_credential: ManagementActorCredential,
        permission: UserPermission,
    ) -> Result<NewUser, UserServiceError> {
        let password = std::mem::take(&mut creation.registration.password);
        let password_hash = hash_password(password)
            .await
            .map_err(|_| UserServiceError::PasswordHash)?;
        repository::insert_user_after_owner(
            &self.pool,
            creation,
            password_hash,
            actor_credential,
            permission,
        )
        .await
        .map_err(|error| match error {
            repository::ManagedUserInsertError::Database(error) => {
                UserServiceError::Database(error)
            }
            repository::ManagedUserInsertError::ManagementActor(error) => {
                UserServiceError::ManagementActor(error)
            }
        })?
        .ok_or(UserServiceError::OwnerBootstrapRequired)
    }

    async fn insert_after_owner_with_audit(
        &self,
        mut creation: UserCreation,
        actor_type: String,
        actor_id: Option<String>,
        actor_credential: ManagementActorCredential,
        permission: UserPermission,
    ) -> Result<NewUser, UserServiceError> {
        let password = std::mem::take(&mut creation.registration.password);
        let password_hash = hash_password(password)
            .await
            .map_err(|_| UserServiceError::PasswordHash)?;
        let user = repository::insert_user_after_owner_with_audit(
            &self.pool,
            creation,
            password_hash,
            actor_credential,
            permission,
            move |user| {
                AuditEvent::new(
                    actor_type,
                    actor_id,
                    crate::audit::AuditAction::UserCreate,
                    "user".to_owned(),
                    Some(user.id.to_string()),
                    serde_json::json!({
                        "role": user.role.as_str(),
                        "status": user.status.as_str(),
                    }),
                )
            },
        )
        .await
        .map_err(|error| match error {
            repository::AuditedUserInsertError::Database(error) => {
                UserServiceError::Database(error)
            }
            repository::AuditedUserInsertError::Audit(error) => {
                tracing::error!(event = "user_creation.audit_unavailable", error = %error);
                UserServiceError::AuditUnavailable
            }
            repository::AuditedUserInsertError::ManagementActor(error) => {
                UserServiceError::ManagementActor(error)
            }
        })?
        .ok_or(UserServiceError::OwnerBootstrapRequired)?;
        Ok(user)
    }

    pub(super) async fn ensure_email_policy_allows(
        &self,
        email: &EmailAddress,
    ) -> Result<(), UserServiceError> {
        crate::users::email_policy::ensure_email_policy_allows(&self.pool, email).await
    }
}

/// Owner 引导成功的审计事件。
///
/// `actor_type` 用 `bootstrap` 与拒绝路径
/// （`crate::admin::bootstrap_guard::record_bootstrap_denial`）保持一致，
/// 因此一次部署的整条引导时间线可以按同一个 actor 检索。
///
/// 元数据只含角色与来源 IP：`source_ip` 在审计脱敏白名单内，用户名、邮箱和口令
/// 都不进审计 —— 前两者属于个人数据，后者是凭据。
fn owner_bootstrap_audit_event(id: UserId, source_ip: Option<&str>) -> crate::audit::AuditEvent {
    crate::audit::AuditEvent::new(
        "bootstrap".to_owned(),
        None,
        crate::audit::AuditAction::OwnerBootstrap,
        "user".to_owned(),
        Some(id.to_string()),
        serde_json::json!({"result": "success", "role": "owner", "source_ip": source_ip}),
    )
}

/// 用落库结果构造对外视图。
///
/// (role, status) 取自 `NewUser` 而不是调用方的入参，响应因此必然与数据库一致。
/// `password_hash` 在此被丢弃，不进入任何响应。
///
/// `email` 取展示值：对外 API 契约里的 `email` 字段一直是给人看的那一串，
/// 匹配值 `canonical_email` 不进任何响应（Issue #302）。
fn public_user(user: NewUser) -> PublicUser {
    PublicUser {
        id: user.id,
        username: user.username,
        email: user.email.into_display(),
        display_name: user.display_name,
        status: user.status.as_str().to_owned(),
        role: user.role,
        created_at: user.created_at,
    }
}
