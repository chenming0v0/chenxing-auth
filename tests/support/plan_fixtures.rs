#![allow(dead_code)]

//! 套餐测试前提的共享脚手架。
//!
//! `migrations/0002_plans.sql` 不再种子任何套餐，「库里没有套餐」是新的默认
//! 状态。因此每个需要套餐的测试必须**显式声明自己的前提**，而不是依赖迁移
//! 或其他测试留下的行。
//!
//! 两类前提：
//! - 全局默认套餐（`seed_default_plan`）：影响所有没有挂载套餐的用户，是共享
//!   状态。`plans` 表上有 `plans_single_default_idx`（唯一的 default），所以
//!   同一时刻只能有一个测试二进制持有它 —— 用 [`SharedPlanLock`] 串行化。
//! - 私有套餐（`assign_private_plan`）：只挂到某个用户上，`is_default = FALSE`，
//!   不参与全局唯一索引。但 `clear_all_plans` 是 `DELETE FROM plans`，会连带
//!   删除私有套餐，所以任何依赖套餐的二进制同样要持锁。

use chenxing_auth::sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

/// 原种子（`migrations/0002_plans.sql` 删除前）的默认套餐 code。
pub const DEFAULT_PLAN_CODE: &str = "basic";

/// 原种子的限额。删除种子后这组数值只存在于这里，语义没丢。
pub const DEFAULT_PLAN_OAUTH_CLIENTS_LIMIT: i32 = 2;
pub const DEFAULT_PLAN_DAILY_AUTH_LIMIT: i64 = 2_500;
pub const DEFAULT_PLAN_MONTHLY_AUTH_LIMIT: i64 = 50_000;

/// 跨测试二进制串行化 `plans` 表的写入。
///
/// 复用 `chenxing-shared-reset` 这一把锁（`admin_api` / `admin_ui_api` /
/// `login_security` / `bootstrap_invariant` / `authorization_audit` 已在用），
/// 只有一把锁就不存在获取顺序造成的死锁。持有到 guard 被 drop（事务结束）。
pub struct SharedPlanLock {
    _connection: PgConnection,
}

pub async fn shared_plan_lock(database_url: &str) -> SharedPlanLock {
    let mut connection = PgConnection::connect(database_url)
        .await
        .expect("plan fixture lock connection");
    chenxing_auth::sqlx::query("BEGIN")
        .execute(&mut connection)
        .await
        .expect("plan fixture lock transaction");
    chenxing_auth::sqlx::query("SELECT pg_advisory_xact_lock(hashtext('chenxing-shared-reset'))")
        .execute(&mut connection)
        .await
        .expect("plan fixture lock");
    SharedPlanLock {
        _connection: connection,
    }
}

/// 清空所有套餐。
///
/// `users.plan_id` 是 `ON DELETE SET NULL`，所以这会顺带解绑所有用户的套餐 ——
/// 这正是「平台未开放自助接入」的目标状态：没有挂载套餐、也没有默认套餐。
pub async fn clear_all_plans(database: &PgPool) {
    chenxing_auth::sqlx::query("DELETE FROM plans")
        .execute(database)
        .await
        .expect("clear all plans");
}

/// 插入原种子等价的 active 默认套餐，返回其 id。
///
/// 调用方负责先 [`clear_all_plans`]（`code` 有唯一约束，`is_default` 有唯一
/// 部分索引，重复插入会冲突）。
pub async fn seed_default_plan(database: &PgPool) -> i64 {
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO plans (code, name, description, oauth_clients_limit, daily_auth_limit,
                            monthly_auth_limit, max_qps, is_default, status)
         VALUES ($1, '基础版', '默认套餐', $2, $3, $4, NULL, TRUE, 'active')
         RETURNING id",
    )
    .bind(DEFAULT_PLAN_CODE)
    .bind(DEFAULT_PLAN_OAUTH_CLIENTS_LIMIT)
    .bind(DEFAULT_PLAN_DAILY_AUTH_LIMIT)
    .bind(DEFAULT_PLAN_MONTHLY_AUTH_LIMIT)
    .fetch_one(database)
    .await
    .expect("seed default plan")
}

/// 一个用户私有套餐的限额。
#[derive(Debug, Clone, Copy)]
pub struct PlanLimits {
    pub oauth_clients_limit: i32,
    pub daily_auth_limit: i64,
    pub monthly_auth_limit: Option<i64>,
    pub max_qps: Option<i32>,
}

impl PlanLimits {
    /// 原种子的限额：既有断言依赖 2 / 2500 / 50000。
    pub fn legacy_default() -> Self {
        Self {
            oauth_clients_limit: DEFAULT_PLAN_OAUTH_CLIENTS_LIMIT,
            daily_auth_limit: DEFAULT_PLAN_DAILY_AUTH_LIMIT,
            monthly_auth_limit: Some(DEFAULT_PLAN_MONTHLY_AUTH_LIMIT),
            max_qps: None,
        }
    }
}

/// 给单个用户挂一个 `is_default = FALSE` 的私有套餐。
///
/// 不碰全局默认套餐，因此多个测试可以各自挂自己的套餐而互不影响。
pub async fn assign_private_plan(database: &PgPool, user_id: i64, limits: PlanLimits) -> i64 {
    let plan_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO plans (code, name, description, oauth_clients_limit, daily_auth_limit,
                            monthly_auth_limit, max_qps, is_default, status)
         VALUES ($1, $1, 'test fixture plan', $2, $3, $4, $5, FALSE, 'active')
         RETURNING id",
    )
    .bind(format!("fixture-{}", Uuid::new_v4().simple()))
    .bind(limits.oauth_clients_limit)
    .bind(limits.daily_auth_limit)
    .bind(limits.monthly_auth_limit)
    .bind(limits.max_qps)
    .fetch_one(database)
    .await
    .expect("insert private plan");
    chenxing_auth::sqlx::query(
        "UPDATE users SET plan_id = $2, plan_expires_at = NULL WHERE id = $1",
    )
    .bind(user_id)
    .bind(plan_id)
    .execute(database)
    .await
    .expect("assign private plan");
    plan_id
}

/// 按用户名挂私有套餐。注册接口不返回 id 的调用点用它。
pub async fn assign_private_plan_by_username(
    database: &PgPool,
    username: &str,
    limits: PlanLimits,
) -> i64 {
    let user_id: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(username)
            .fetch_one(database)
            .await
            .expect("user id for private plan");
    assign_private_plan(database, user_id, limits).await
}

/// active 且 `is_default` 的套餐数量。新语义下 0 是合法值。
pub async fn active_default_plan_count(database: &PgPool) -> i64 {
    chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(id) FROM plans WHERE is_default = TRUE AND status = 'active'",
    )
    .fetch_one(database)
    .await
    .expect("active default plan count")
}

/// 读取套餐的 `(status, is_default)`。
pub async fn plan_status_and_default(database: &PgPool, plan_id: i64) -> (String, bool) {
    chenxing_auth::sqlx::query_as("SELECT status, is_default FROM plans WHERE id = $1")
        .bind(plan_id)
        .fetch_one(database)
        .await
        .expect("plan status and default flag")
}
