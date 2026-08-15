use thiserror::Error;
use time::OffsetDateTime;

use super::{
    domain::{
        Plan, PlanMutationError, ValidatedPlanInput, validate_plan_assignment, validate_plan_update,
    },
    service::EffectivePlan,
};
use crate::db::advisory_lock::{BusinessLock, lock_business};
use crate::sqlx::{PgPool, Postgres, Transaction};
use crate::users::domain::{OwnerTargetAccess, UserId};

#[derive(Debug, Error)]
pub enum PlanRepositoryError {
    #[error(transparent)]
    Database(#[from] crate::sqlx::Error),
    #[error(transparent)]
    Mutation(#[from] PlanMutationError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanAssignmentResult {
    PlanNotFound,
    UserNotFound,
    ManageRolesRequired,
    Assigned,
}

#[derive(Debug)]
pub struct PlanWithUsers {
    pub plan: Plan,
    pub assigned_users: i64,
}

/// plans 表 12 列（含 created_at / updated_at），按列顺序与 SQL 一一对应。
type PlanRow = (
    i64,
    String,
    String,
    Option<String>,
    i32,
    i64,
    Option<i64>,
    Option<i32>,
    bool,
    String,
    OffsetDateTime,
    OffsetDateTime,
);

/// plans 12 列 + 挂载用户数（`COUNT(u.id)` 恒为非空整数）。
type PlanRowWithCount = (
    i64,
    String,
    String,
    Option<String>,
    i32,
    i64,
    Option<i64>,
    Option<i32>,
    bool,
    String,
    OffsetDateTime,
    OffsetDateTime,
    i64,
);

/// plans 12 列 + 用户到期时间（`NULL` 表示永久有效）。
type PlanRowWithExpiry = (
    i64,
    String,
    String,
    Option<String>,
    i32,
    i64,
    Option<i64>,
    Option<i32>,
    bool,
    String,
    OffsetDateTime,
    OffsetDateTime,
    Option<OffsetDateTime>,
);

fn row_to_plan(row: PlanRow) -> Plan {
    Plan {
        id: row.0,
        code: row.1,
        name: row.2,
        description: row.3,
        oauth_clients_limit: row.4,
        daily_auth_limit: row.5,
        monthly_auth_limit: row.6,
        max_qps: row.7,
        is_default: row.8,
        status: row.9,
        created_at: row.10,
        updated_at: row.11,
    }
}

pub async fn list_plans(pool: &PgPool) -> Result<Vec<PlanWithUsers>, crate::sqlx::Error> {
    let rows: Vec<PlanRowWithCount> = crate::sqlx::query_as(
        "SELECT p.id, p.code, p.name, p.description, p.oauth_clients_limit, p.daily_auth_limit,
                p.monthly_auth_limit, p.max_qps, p.is_default, p.status, p.created_at, p.updated_at,
                COUNT(u.id)
         FROM plans p
         LEFT JOIN users u ON u.plan_id = p.id
         GROUP BY p.id, p.code, p.name, p.description, p.oauth_clients_limit, p.daily_auth_limit,
                  p.monthly_auth_limit, p.max_qps, p.is_default, p.status, p.created_at, p.updated_at
         ORDER BY p.created_at, p.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PlanWithUsers {
            plan: row_to_plan((
                row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9, row.10,
                row.11,
            )),
            assigned_users: row.12,
        })
        .collect())
}

pub async fn find_by_id(pool: &PgPool, id: i64) -> Result<Option<Plan>, crate::sqlx::Error> {
    let row: Option<PlanRow> = crate::sqlx::query_as(
        "SELECT id, code, name, description, oauth_clients_limit, daily_auth_limit,
                monthly_auth_limit, max_qps, is_default, status, created_at, updated_at
         FROM plans WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(row_to_plan))
}

pub async fn find_default(pool: &PgPool) -> Result<Option<Plan>, crate::sqlx::Error> {
    let row: Option<PlanRow> = crate::sqlx::query_as(
        "SELECT id, code, name, description, oauth_clients_limit, daily_auth_limit,
                monthly_auth_limit, max_qps, is_default, status, created_at, updated_at
         FROM plans WHERE is_default = TRUE AND status = 'active' LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(row_to_plan))
}

/// 读取用户当前挂载且仍有效的套餐；未挂载、已归档或已过期时返回 `None`，
/// 由 service 层回退到默认套餐。
pub async fn find_for_user(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Option<EffectivePlan>, crate::sqlx::Error> {
    let row: Option<PlanRowWithExpiry> = crate::sqlx::query_as(
        "SELECT p.id, p.code, p.name, p.description, p.oauth_clients_limit, p.daily_auth_limit,
                p.monthly_auth_limit, p.max_qps, p.is_default, p.status, p.created_at, p.updated_at,
                u.plan_expires_at
         FROM plans p
         JOIN users u ON u.plan_id = p.id
         WHERE u.id = $1
           AND p.status = 'active'
           AND (u.plan_expires_at IS NULL OR u.plan_expires_at > NOW())",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| EffectivePlan {
        plan: row_to_plan((
            row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9, row.10, row.11,
        )),
        expires_at: row.12,
    }))
}

async fn lock_default_plan_set(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), crate::sqlx::Error> {
    lock_business(transaction, BusinessLock::DefaultPlan).await
}

async fn find_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<Option<Plan>, crate::sqlx::Error> {
    let row: Option<PlanRow> = crate::sqlx::query_as(
        "SELECT id, code, name, description, oauth_clients_limit, daily_auth_limit,
                monthly_auth_limit, max_qps, is_default, status, created_at, updated_at
         FROM plans WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(row_to_plan))
}

/// 统计挂载到指定套餐的用户数。在事务内调用，保证与刚写入的套餐处于同一快照。
async fn count_assigned_users(
    transaction: &mut Transaction<'_, Postgres>,
    plan_id: i64,
) -> Result<i64, crate::sqlx::Error> {
    crate::sqlx::query_scalar("SELECT COUNT(id) FROM users WHERE plan_id = $1")
        .bind(plan_id)
        .fetch_one(&mut **transaction)
        .await
}

pub async fn insert(
    pool: &PgPool,
    input: &ValidatedPlanInput,
) -> Result<Plan, PlanRepositoryError> {
    let mut transaction = pool.begin().await?;
    lock_default_plan_set(&mut transaction).await?;
    if input.is_default {
        crate::sqlx::query("UPDATE plans SET is_default = FALSE WHERE is_default = TRUE")
            .execute(&mut *transaction)
            .await?;
    }
    let row: PlanRow = crate::sqlx::query_as(
        "INSERT INTO plans (code, name, description, oauth_clients_limit, daily_auth_limit,
                            monthly_auth_limit, max_qps, is_default, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', NOW(), NOW())
         RETURNING id, code, name, description, oauth_clients_limit, daily_auth_limit,
                   monthly_auth_limit, max_qps, is_default, status, created_at, updated_at",
    )
    .bind(&input.code)
    .bind(&input.name)
    .bind(&input.description)
    .bind(input.oauth_clients_limit)
    .bind(input.daily_auth_limit)
    .bind(input.monthly_auth_limit)
    .bind(input.max_qps)
    .bind(input.is_default)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(row_to_plan(row))
}

pub async fn update(
    pool: &PgPool,
    id: i64,
    input: &ValidatedPlanInput,
) -> Result<Option<PlanWithUsers>, PlanRepositoryError> {
    let mut transaction = pool.begin().await?;
    lock_default_plan_set(&mut transaction).await?;
    let Some(current) = find_for_update(&mut transaction, id).await? else {
        transaction.rollback().await?;
        return Ok(None);
    };
    validate_plan_update(&current, input)?;
    if input.is_default {
        crate::sqlx::query(
            "UPDATE plans SET is_default = FALSE WHERE is_default = TRUE AND id <> $1",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    }
    let row: PlanRow = crate::sqlx::query_as(
        "UPDATE plans SET code = $2, name = $3, description = $4, oauth_clients_limit = $5,
                daily_auth_limit = $6, monthly_auth_limit = $7, max_qps = $8, is_default = $9,
                updated_at = NOW()
         WHERE id = $1
         RETURNING id, code, name, description, oauth_clients_limit, daily_auth_limit,
                   monthly_auth_limit, max_qps, is_default, status, created_at, updated_at",
    )
    .bind(id)
    .bind(&input.code)
    .bind(&input.name)
    .bind(&input.description)
    .bind(input.oauth_clients_limit)
    .bind(input.daily_auth_limit)
    .bind(input.monthly_auth_limit)
    .bind(input.max_qps)
    .bind(input.is_default)
    .fetch_one(&mut *transaction)
    .await?;
    // 更新成功后在同一事务中统计挂载用户数；避免提交后再查询时失败导致响应丢失更新结果
    let assigned_users = count_assigned_users(&mut transaction, id).await?;
    transaction.commit().await?;
    Ok(Some(PlanWithUsers {
        plan: row_to_plan(row),
        assigned_users,
    }))
}

/// 归档 / 恢复套餐。归档时同一条 UPDATE 顺手清掉默认标记：默认套餐必须是
/// active（`plans_default_must_be_active`），而「系统没有默认套餐」是合法状态，
/// 因此不需要为「被归档的正是默认套餐」单开分支。
/// 仍然持有 advisory lock，避免与 `insert` / `update` 的 is_default 切换交错，
/// 让唯一索引和 CHECK 约束不必依赖并发时序。
pub async fn set_status(pool: &PgPool, id: i64, status: &str) -> Result<bool, PlanRepositoryError> {
    let mut transaction = pool.begin().await?;
    lock_default_plan_set(&mut transaction).await?;
    let result = crate::sqlx::query(
        "UPDATE plans
         SET status = $2, is_default = (is_default AND $2 = 'active'), updated_at = NOW()
         WHERE id = $1",
    )
    .bind(id)
    .bind(status)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(false);
    }
    transaction.commit().await?;
    Ok(true)
}

pub async fn assign_to_user(
    pool: &PgPool,
    user_id: UserId,
    plan_id: i64,
    expires_at: Option<OffsetDateTime>,
    access: OwnerTargetAccess,
) -> Result<PlanAssignmentResult, PlanRepositoryError> {
    let mut transaction = pool.begin().await?;
    // 先锁目标用户，再判定 Owner 档位；该锁一直持有到套餐写入提交。角色晋升与
    // 套餐改写因此不可能穿过两个独立快照（Issue #323）。目标先于套餐判定也保留
    // 既有错误优先级：Owner 权限不足仍是 403，而不是由套餐状态泄露 404/400。
    let role: Option<String> =
        crate::sqlx::query_scalar("SELECT role FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?;
    let Some(role) = role else {
        transaction.rollback().await?;
        return Ok(PlanAssignmentResult::UserNotFound);
    };
    if role == "owner" && !access.permits_owner() {
        transaction.rollback().await?;
        return Ok(PlanAssignmentResult::ManageRolesRequired);
    }
    lock_default_plan_set(&mut transaction).await?;
    let Some(plan) = find_for_update(&mut transaction, plan_id).await? else {
        transaction.rollback().await?;
        return Ok(PlanAssignmentResult::PlanNotFound);
    };
    validate_plan_assignment(&plan)?;
    let result = crate::sqlx::query(
        "UPDATE users SET plan_id = $2, plan_expires_at = $3, updated_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .bind(plan_id)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    // 目标行从角色判定开始一直由本事务持锁，正常路径必然更新一行；仍保留防御性
    // 判定，避免数据库触发器或未来 SQL 改动把零行更新误报成成功。
    if result.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(PlanAssignmentResult::UserNotFound);
    }
    transaction.commit().await?;
    Ok(PlanAssignmentResult::Assigned)
}
