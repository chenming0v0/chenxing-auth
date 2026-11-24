//! 事务内的套餐锁定与到期回退，供自助 Client 配额检查和插入共用。

use super::{find_default_for_update, find_for_update, lock_default_plan_set, map_plan_row};
use crate::{
    plans::{domain::Plan, row::PlanRow},
    sqlx::{Postgres, Transaction},
    users::domain::UserId,
};

/// 调用方提供 decision_time(at) 和用户参数 $1。读锁后解析与最终 INSERT 使用同一
/// 选择规则，避免到期回退时错误合并 nullable 配额（例如无限月额度）。
pub(crate) const EFFECTIVE_PLAN_FROM_USER: &str = "FROM users u
     CROSS JOIN decision_time
     LEFT JOIN plans assigned_plan
       ON assigned_plan.id = u.plan_id AND assigned_plan.status = 'active'
      AND (u.plan_expires_at IS NULL OR u.plan_expires_at > decision_time.at)
     LEFT JOIN plans default_plan
       ON default_plan.is_default = TRUE AND default_plan.status = 'active'
     JOIN plans p ON p.id = COALESCE(assigned_plan.id, default_plan.id)
     WHERE u.id = $1";

/// 保持用户行 → DefaultPlan 业务锁 → 套餐行的偏序，同时锁定显式套餐和默认套餐。
/// 默认套餐也必须锁住，因为用户的显式套餐可能在本事务后续 INSERT 前自然到期。
pub(crate) async fn lock_effective_for_user(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
) -> Result<Option<Plan>, crate::sqlx::Error> {
    let assigned_plan_id: Option<i64> =
        crate::sqlx::query_scalar("SELECT plan_id FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut **transaction)
            .await?;

    lock_default_plan_set(transaction).await?;
    if let Some(plan_id) = assigned_plan_id {
        let _ = find_for_update(transaction, plan_id).await?;
    }
    let _ = find_default_for_update(transaction).await?;
    // 必须另发语句：锁语句的 statement_timestamp() 也可能早于锁等待结束。
    find_effective_for_locked_user(transaction, user_id).await
}

/// 调用方已持有用户、默认套餐集合和套餐行锁；本语句只重新判断自然到期。
/// clock_timestamp() 来自同一数据库，在长事务与幂等 claim 等待后仍反映当前时间。
pub(crate) async fn find_effective_for_locked_user(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
) -> Result<Option<Plan>, crate::sqlx::Error> {
    let row: Option<PlanRow> = crate::sqlx::query_as(&format!(
        "WITH decision_time AS MATERIALIZED (SELECT clock_timestamp() AS at)
         SELECT p.id, p.code, p.name, p.description, p.oauth_clients_limit, p.daily_auth_limit,
                p.monthly_auth_limit, p.max_qps, p.is_default, p.status, p.price_points,
                p.billing_period, p.created_at, p.updated_at
         {EFFECTIVE_PLAN_FROM_USER}"
    ))
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?;
    row.map(map_plan_row).transpose()
}
