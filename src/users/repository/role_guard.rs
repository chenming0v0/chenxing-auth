//! 角色与状态守卫。
//!
//! 两个函数共享同一条领域规则：系统必须始终保留至少一个活跃 Owner。
//! 降级最后一个活跃 Owner 的角色，或禁用最后一个活跃 Owner 的账号，都会让
//! 管理面永久失去最高权限持有者，因此在事务内加锁判定后直接拒绝。
//!
//! 判定顺序固定：先 `FOR UPDATE` 锁住全部活跃 Owner 行，再锁目标行。
//! 两个并发请求各自降级两个仅存 Owner 中的一个时，锁序保证后者能看到前者的结果，
//! 不会出现"两个请求各自认为还剩一个 Owner"的竞态。

use crate::sqlx::PgPool;

use crate::users::domain::{UserId, UserRole, UserStatus};

/// 角色变更的业务结果。
///
/// 「最后一个活跃 Owner 不能降级」是领域规则，不是数据库故障。旧实现用
/// `sqlx::Error::Protocol("last active owner required")` 携带它，服务层再用
/// `message.contains(...)` 把字符串翻译回业务语义：错误通道被借用来传业务状态，
/// 判定依赖一个没有类型约束的字符串常量，任何改写措辞的提交都会静默破坏守卫。
/// 用枚举把三种终局显式化，调用方 match 时由编译器保证覆盖完整。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetRoleOutcome {
    /// 角色已更新。
    Updated,
    /// 目标用户不存在。
    NotFound,
    /// 拒绝降级：这是最后一个活跃 Owner。
    LastOwnerRequired,
}

/// 读取当前活跃 Owner 数量与目标用户的 (role, status)，两者都加行锁。
///
/// 返回 `None` 表示目标用户不存在。调用方负责回滚事务。
async fn lock_owner_scope(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    id: UserId,
) -> Result<(usize, Option<(String, String)>), crate::sqlx::Error> {
    let active_owners: Vec<(UserId,)> = crate::sqlx::query_as(
        "SELECT id FROM users WHERE role = 'owner' AND status = 'active' ORDER BY id FOR UPDATE",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let current: Option<(String, String)> =
        crate::sqlx::query_as("SELECT role, status FROM users WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **transaction)
            .await?;
    Ok((active_owners.len(), current))
}

pub async fn set_user_role(
    pool: &PgPool,
    id: UserId,
    role: UserRole,
) -> Result<SetRoleOutcome, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let (active_owner_count, current) = lock_owner_scope(&mut transaction, id).await?;
    let Some((current_role, status)) = current else {
        transaction.rollback().await?;
        return Ok(SetRoleOutcome::NotFound);
    };
    if current_role == "owner"
        && role != UserRole::Owner
        && status == "active"
        && active_owner_count <= 1
    {
        transaction.rollback().await?;
        return Ok(SetRoleOutcome::LastOwnerRequired);
    }
    crate::sqlx::query("UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .bind(role.as_str())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(SetRoleOutcome::Updated)
}

pub async fn set_user_status(
    pool: &crate::sqlx::PgPool,
    id: UserId,
    status: &str,
) -> Result<bool, crate::sqlx::Error> {
    Ok(matches!(
        set_user_status_guarded(pool, id, status).await?,
        Some("updated")
    ))
}

pub async fn set_user_status_guarded(
    pool: &PgPool,
    id: UserId,
    status: &str,
) -> Result<Option<&'static str>, crate::sqlx::Error> {
    // 状态词表只有 `UserStatus` 一个来源：这里曾经内联 `matches!(status, "active" | "disabled")`，
    // 与领域枚举和数据库 CHECK 约束构成第三份副本。返回语义保持不变——
    // 非法状态仍然按"未找到"处理（调用方翻成 400 user_not_found）。
    if UserStatus::parse(status).is_none() {
        return Ok(None);
    }
    let mut transaction = pool.begin().await?;
    crate::sessions::store::lock_user_session_scope(&mut transaction, id).await?;
    let (active_owner_count, current) = lock_owner_scope(&mut transaction, id).await?;
    let Some((role, current_status)) = current else {
        transaction.rollback().await?;
        return Ok(None);
    };
    if role == "owner"
        && current_status == "active"
        && status == "disabled"
        && active_owner_count <= 1
    {
        transaction.rollback().await?;
        return Ok(Some("last_owner_required"));
    }
    // 禁用即撤销该用户全部会话：否则被禁用的账号仍能用既有 Cookie 继续访问。
    if current_status != status && status == "disabled" {
        crate::sessions::store::revoke_all_for_user_in_transaction(&mut transaction, id).await?;
    }
    let result =
        crate::sqlx::query("UPDATE users SET status = $2, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(&mut *transaction)
            .await?;
    transaction.commit().await?;
    Ok((result.rows_affected() == 1).then_some("updated"))
}
