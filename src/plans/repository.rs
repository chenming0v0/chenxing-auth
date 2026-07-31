use time::OffsetDateTime;

use super::{
    domain::{Plan, ValidatedPlanInput},
    service::EffectivePlan,
};
use crate::sqlx::PgPool;
use crate::users::domain::UserId;

/// 串行化 `is_default` 切换的 advisory lock，与用户引导锁区分开。
const DEFAULT_PLAN_LOCK: i64 = 7341929;

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

pub async fn insert(pool: &PgPool, input: &ValidatedPlanInput) -> Result<Plan, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(DEFAULT_PLAN_LOCK)
        .execute(&mut *transaction)
        .await?;
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
) -> Result<bool, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(DEFAULT_PLAN_LOCK)
        .execute(&mut *transaction)
        .await?;
    if input.is_default {
        crate::sqlx::query(
            "UPDATE plans SET is_default = FALSE WHERE is_default = TRUE AND id <> $1",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    }
    let result = crate::sqlx::query(
        "UPDATE plans SET code = $2, name = $3, description = $4, oauth_clients_limit = $5,
                daily_auth_limit = $6, monthly_auth_limit = $7, max_qps = $8, is_default = $9,
                updated_at = NOW()
         WHERE id = $1",
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
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(result.rows_affected() == 1)
}

pub async fn set_status(pool: &PgPool, id: i64, status: &str) -> Result<bool, crate::sqlx::Error> {
    let result =
        crate::sqlx::query("UPDATE plans SET status = $2, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn assign_to_user(
    pool: &PgPool,
    user_id: UserId,
    plan_id: i64,
    expires_at: Option<OffsetDateTime>,
) -> Result<bool, crate::sqlx::Error> {
    let result = crate::sqlx::query(
        "UPDATE users SET plan_id = $2, plan_expires_at = $3, updated_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .bind(plan_id)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}
