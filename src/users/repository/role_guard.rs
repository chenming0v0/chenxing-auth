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

/// 受 Owner 守卫保护的写操作的业务结果，角色变更与状态变更共用。
///
/// 「最后一个活跃 Owner 不能降级/禁用」是领域规则，不是数据库故障。历史实现用过
/// 两种代用通道，都被这个枚举取代：
///
/// - `set_user_role` 曾用 `sqlx::Error::Protocol("last active owner required")` 携带它，
///   服务层再 `message.contains(...)` 翻译回业务语义 —— 判定依赖一个没有类型约束的
///   字符串常量，任何改写措辞的提交都会静默破坏守卫。
/// - `set_user_status_guarded` 曾返回 `Option<&'static str>`（`Some("updated")` /
///   `Some("last_owner_required")` / `None`），服务层的 `_ => Ok(false)` 兜底分支
///   会把任何未识别的字符串静默降级成「用户不存在」（Issue #283）。
///
/// 三种终局显式化后，调用方 match 时由编译器保证覆盖完整，不存在兜底分支。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerGuardOutcome {
    /// 写入已提交。
    Updated,
    /// 目标用户不存在。
    NotFound,
    /// 拒绝：这是最后一个活跃 Owner。
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
) -> Result<OwnerGuardOutcome, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let (active_owner_count, current) = lock_owner_scope(&mut transaction, id).await?;
    let Some((current_role, status)) = current else {
        transaction.rollback().await?;
        return Ok(OwnerGuardOutcome::NotFound);
    };
    if current_role == "owner"
        && role != UserRole::Owner
        && UserStatus::parse(&status) == Some(UserStatus::Active)
        && active_owner_count <= 1
    {
        transaction.rollback().await?;
        return Ok(OwnerGuardOutcome::LastOwnerRequired);
    }
    crate::sqlx::query("UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .bind(role.as_str())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(OwnerGuardOutcome::Updated)
}

/// 变更用户状态。
///
/// 入参是已解析的 [`UserStatus`]，因此本函数不存在「状态串非法」这一终局 ——
/// 非法输入在 HTTP 层就被拒为 400，不会走到仓储层（Issue #283）。
pub async fn set_user_status_guarded(
    pool: &PgPool,
    id: UserId,
    status: UserStatus,
) -> Result<OwnerGuardOutcome, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    crate::sessions::store::lock_user_session_scope(&mut transaction, id).await?;
    let (active_owner_count, current) = lock_owner_scope(&mut transaction, id).await?;
    let Some((role, current_status)) = current else {
        transaction.rollback().await?;
        return Ok(OwnerGuardOutcome::NotFound);
    };
    let current_status = UserStatus::parse(&current_status);
    if role == "owner"
        && current_status == Some(UserStatus::Active)
        && status == UserStatus::Disabled
        && active_owner_count <= 1
    {
        transaction.rollback().await?;
        return Ok(OwnerGuardOutcome::LastOwnerRequired);
    }
    // 禁用即撤销该用户全部会话：否则被禁用的账号仍能用既有 Cookie 继续访问。
    if current_status != Some(status) && status == UserStatus::Disabled {
        crate::sessions::store::revoke_all_for_user_in_transaction(&mut transaction, id).await?;
    }
    let result =
        crate::sqlx::query("UPDATE users SET status = $2, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(status.as_str())
            .execute(&mut *transaction)
            .await?;
    transaction.commit().await?;
    // 目标行已在 `lock_owner_scope` 里加锁，正常路径必然影响 1 行；
    // 这里保留判定是为了不把「行在锁定后消失」当成成功。
    Ok(if result.rows_affected() == 1 {
        OwnerGuardOutcome::Updated
    } else {
        OwnerGuardOutcome::NotFound
    })
}
