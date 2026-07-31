use thiserror::Error;
use time::OffsetDateTime;

pub use super::repository::PlanWithUsers;
use super::{
    domain::{Plan, PlanError, PlanInput, validate_plan_input},
    repository::{self},
};
use crate::sqlx::PgPool;
use crate::users::domain::UserId;

#[derive(Clone)]
pub struct PlanService {
    pool: PgPool,
}

#[derive(Debug, Error)]
pub enum PlanServiceError {
    #[error(transparent)]
    Validation(#[from] PlanError),
    #[error("plan was not found")]
    NotFound,
    #[error("plan code is already registered")]
    CodeConflict,
    #[error("the default plan cannot be archived")]
    DefaultPlanProtected,
    #[error("archived plans cannot be assigned to users")]
    PlanArchived,
    #[error("user was not found")]
    UserNotFound,
    #[error("no default plan is configured")]
    NoDefaultPlan,
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
        Self { pool }
    }

    pub async fn list(&self) -> Result<Vec<PlanWithUsers>, PlanServiceError> {
        Ok(repository::list_plans(&self.pool).await?)
    }

    pub async fn create(&self, input: PlanInput) -> Result<Plan, PlanServiceError> {
        let input = validate_plan_input(input)?;
        match repository::insert(&self.pool, &input).await {
            Ok(plan) => Ok(plan),
            Err(error) if is_unique_violation(&error) => Err(PlanServiceError::CodeConflict),
            Err(error) => Err(PlanServiceError::Database(error)),
        }
    }

    pub async fn update(&self, id: i64, input: PlanInput) -> Result<Plan, PlanServiceError> {
        let input = validate_plan_input(input)?;
        if !repository::update(&self.pool, id, &input).await? {
            return Err(PlanServiceError::NotFound);
        }
        repository::find_by_id(&self.pool, id)
            .await?
            .ok_or(PlanServiceError::NotFound)
    }

    pub async fn archive(&self, id: i64) -> Result<(), PlanServiceError> {
        let Some(plan) = repository::find_by_id(&self.pool, id).await? else {
            return Err(PlanServiceError::NotFound);
        };
        if plan.is_default {
            return Err(PlanServiceError::DefaultPlanProtected);
        }
        if !repository::set_status(&self.pool, id, "archived").await? {
            return Err(PlanServiceError::NotFound);
        }
        Ok(())
    }

    pub async fn restore(&self, id: i64) -> Result<(), PlanServiceError> {
        if !repository::set_status(&self.pool, id, "active").await? {
            return Err(PlanServiceError::NotFound);
        }
        Ok(())
    }

    pub async fn assign_to_user(
        &self,
        user_id: UserId,
        plan_id: i64,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<(), PlanServiceError> {
        if expires_at.is_some_and(|value| value <= OffsetDateTime::now_utc()) {
            return Err(PlanServiceError::Validation(PlanError::ExpiryInPast));
        }
        let Some(plan) = repository::find_by_id(&self.pool, plan_id).await? else {
            return Err(PlanServiceError::NotFound);
        };
        if plan.status != "active" {
            return Err(PlanServiceError::PlanArchived);
        }
        if !repository::assign_to_user(&self.pool, user_id, plan_id, expires_at).await? {
            return Err(PlanServiceError::UserNotFound);
        }
        Ok(())
    }

    /// 用户的生效套餐：优先返回其挂载且未过期的套餐，否则回退到默认套餐。
    /// 过期回退的语义是「到期后按默认套餐继续服务」，不自动改写用户记录。
    pub async fn effective_plan_for_user(
        &self,
        user_id: UserId,
    ) -> Result<EffectivePlan, PlanServiceError> {
        if let Some(effective) = repository::find_for_user(&self.pool, user_id).await? {
            return Ok(effective);
        }
        let plan = repository::find_default(&self.pool)
            .await?
            .ok_or(PlanServiceError::NoDefaultPlan)?;
        Ok(EffectivePlan {
            plan,
            expires_at: None,
        })
    }
}

fn is_unique_violation(error: &crate::sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23505")
}
