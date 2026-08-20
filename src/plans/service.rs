use thiserror::Error;
use time::OffsetDateTime;

pub use super::repository::PlanWithUsers;
use super::{
    domain::{
        Plan, PlanError, PlanInput, PlanMutationError, validate_plan_input, validate_plan_update,
    },
    repository::{self, PlanAssignmentResult, PlanRepositoryError},
};
use crate::audit::AuditEvent;
use crate::clock::SharedClock;
use crate::sqlx::PgPool;
use crate::users::{ManagementActorCredential, domain::UserId};

#[derive(Clone)]
pub struct PlanService {
    pool: PgPool,
    /// 只用于「到期时间是否已过」这一类入参校验。
    ///
    /// 生效套餐的权威判定在 SQL 里比较 `plan_expires_at > NOW()`（见
    /// `repository`），那是数据库事务时间，不改读进程时钟。
    clock: SharedClock,
}

#[derive(Debug, Error)]
pub enum PlanServiceError {
    #[error(transparent)]
    Validation(#[from] PlanError),
    #[error("plan was not found")]
    NotFound,
    #[error("plan code is already registered")]
    CodeConflict,
    #[error("archived plans cannot be default")]
    ArchivedPlanCannotBeDefault,
    #[error("archived plans cannot be assigned to users")]
    PlanArchived,
    #[error("user was not found")]
    UserNotFound,
    #[error("managing an owner requires role management permission")]
    ManageRolesRequired,
    #[error("the management actor session is no longer valid")]
    ActorSessionInvalid,
    #[error("the management actor no longer has the required permission")]
    ActorPermissionRequired,
    #[error(transparent)]
    ManagementActor(#[from] crate::users::ManagementActorValidationError),
    #[error("plan audit operation failed: {0}")]
    Audit(#[from] crate::audit::AuditError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

/// 用户当前生效的套餐及其到期时间；`expires_at = None` 表示永久有效。
#[derive(Debug, Clone)]
pub struct EffectivePlan {
    pub plan: Plan,
    pub expires_at: Option<OffsetDateTime>,
}

impl PlanService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            clock: SharedClock::system(),
        }
    }

    /// 注入共享时钟（`AppState` 构造时调用）。
    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

    pub async fn list(&self) -> Result<Vec<PlanWithUsers>, PlanServiceError> {
        Ok(repository::list_plans(&self.pool).await?)
    }

    pub async fn create(
        &self,
        input: PlanInput,
        credential: ManagementActorCredential,
        audit_event: AuditEvent,
    ) -> Result<Plan, PlanServiceError> {
        let input = validate_plan_input(input)?;
        match repository::insert(&self.pool, &input, credential, audit_event).await {
            Ok(plan) => Ok(plan),
            Err(PlanRepositoryError::Database(error)) if is_unique_violation(&error) => {
                Err(PlanServiceError::CodeConflict)
            }
            Err(error) => Err(map_repository_error(error)),
        }
    }

    /// 更新套餐，返回更新后的套餐及同一事务中统计的已分配用户数。
    pub async fn update(
        &self,
        id: i64,
        input: PlanInput,
        credential: ManagementActorCredential,
        audit_event: AuditEvent,
    ) -> Result<PlanWithUsers, PlanServiceError> {
        let input = validate_plan_input(input)?;
        let Some(current) = repository::find_by_id(&self.pool, id).await? else {
            return Err(PlanServiceError::NotFound);
        };
        validate_plan_update(&current, &input).map_err(map_mutation_error)?;
        match repository::update(&self.pool, id, &input, credential, audit_event).await {
            Ok(Some(plan_with_users)) => Ok(plan_with_users),
            Ok(None) => Err(PlanServiceError::NotFound),
            Err(PlanRepositoryError::Database(error)) if is_unique_violation(&error) => {
                Err(PlanServiceError::CodeConflict)
            }
            Err(error) => Err(map_repository_error(error)),
        }
    }

    /// 归档套餐。归档默认套餐是允许的：结果是「平台没有生效默认套餐」，
    /// 语义为未开放自助接入，而不是错误。
    pub async fn archive(
        &self,
        id: i64,
        credential: ManagementActorCredential,
        audit_event: AuditEvent,
    ) -> Result<(), PlanServiceError> {
        self.set_status(id, "archived", credential, audit_event).await
    }

    pub async fn restore(
        &self,
        id: i64,
        credential: ManagementActorCredential,
        audit_event: AuditEvent,
    ) -> Result<(), PlanServiceError> {
        self.set_status(id, "active", credential, audit_event).await
    }

    async fn set_status(
        &self,
        id: i64,
        status: &str,
        credential: ManagementActorCredential,
        audit_event: AuditEvent,
    ) -> Result<(), PlanServiceError> {
        if repository::set_status(&self.pool, id, status, credential, audit_event)
            .await
            .map_err(map_repository_error)?
        {
            Ok(())
        } else {
            Err(PlanServiceError::NotFound)
        }
    }

    pub async fn assign_to_user(
        &self,
        user_id: UserId,
        plan_id: i64,
        expires_at: Option<OffsetDateTime>,
        credential: ManagementActorCredential,
        audit_event: AuditEvent,
    ) -> Result<(), PlanServiceError> {
        if expires_at.is_some_and(|value| value <= self.clock.now()) {
            return Err(PlanServiceError::Validation(PlanError::ExpiryInPast));
        }
        // 套餐存在性与状态由仓储在目标用户锁定之后校验。事务外预查不但重复，
        // 还会让 Owner 权限错误退化成套餐资源预言机。
        match repository::assign_to_user(
            &self.pool,
            user_id,
            plan_id,
            expires_at,
            credential,
            audit_event,
        )
        .await
        .map_err(map_repository_error)?
        {
            PlanAssignmentResult::PlanNotFound => return Err(PlanServiceError::NotFound),
            PlanAssignmentResult::UserNotFound => return Err(PlanServiceError::UserNotFound),
            PlanAssignmentResult::ManageRolesRequired => {
                return Err(PlanServiceError::ManageRolesRequired);
            }
            PlanAssignmentResult::ActorSessionInvalid => {
                return Err(PlanServiceError::ActorSessionInvalid);
            }
            PlanAssignmentResult::ActorPermissionRequired => {
                return Err(PlanServiceError::ActorPermissionRequired);
            }
            PlanAssignmentResult::Assigned => {}
        }
        Ok(())
    }

    /// 用户的生效套餐：挂载且未过期的套餐 → active 默认套餐 → `None`。
    /// 过期回退的语义是「到期后按默认套餐继续服务」，不自动改写用户记录。
    /// `None` 表示平台未开放自助接入，是合法状态而非错误：调用方据此决定
    /// 拒绝新增（自助接入闸门）还是跳过计量（不打死既有集成）。
    pub async fn effective_plan_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Option<EffectivePlan>, PlanServiceError> {
        if let Some(effective) = repository::find_for_user(&self.pool, user_id).await? {
            return Ok(Some(effective));
        }
        Ok(repository::find_default(&self.pool)
            .await?
            .map(|plan| EffectivePlan {
                plan,
                expires_at: None,
            }))
    }
}

fn is_unique_violation(error: &crate::sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23505")
}

fn map_mutation_error(error: PlanMutationError) -> PlanServiceError {
    match error {
        PlanMutationError::ArchivedPlanCannotBeDefault => {
            PlanServiceError::ArchivedPlanCannotBeDefault
        }
        PlanMutationError::PlanArchived => PlanServiceError::PlanArchived,
    }
}

fn map_repository_error(error: PlanRepositoryError) -> PlanServiceError {
    match error {
        PlanRepositoryError::Database(error) => PlanServiceError::Database(error),
        PlanRepositoryError::Mutation(error) => map_mutation_error(error),
        PlanRepositoryError::ManagementActor(error) => PlanServiceError::ManagementActor(error),
        PlanRepositoryError::Audit(error) => PlanServiceError::Audit(error),
    }
}
