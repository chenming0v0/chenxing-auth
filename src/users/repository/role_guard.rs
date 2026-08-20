//! 角色与状态守卫。
//!
//! 两个函数共享同一条领域规则：系统必须始终保留至少一个活跃 Owner。
//! 降级最后一个活跃 Owner 的角色，或禁用最后一个活跃 Owner 的账号，都会让
//! 管理面永久失去最高权限持有者，因此在事务内加锁判定后直接拒绝。
//!
//! 锁顺序固定（Issue #493）：先按用户 ID 升序取得 actor/target 的用户级 advisory
//! lock，再 `FOR UPDATE` 锁住全部活跃 Owner 行，最后按用户 ID 升序锁 actor/target
//! 行。角色变化、状态变化、会话签发和凭据撤销因此共享同一把用户级排序锁；即使两个
//! 管理员同时执行 A 管 B / B 管 A，也不会形成 actor/target 倒锁。
//!
//! 「活跃」的判定口径在 [`UserStatus::is_active`] 与 `lock_active_owner_scope` 的 SQL 谓词
//! `status <> 'disabled'` 之间必须保持一致（Issue #358）：任何未明确禁用的状态串都按
//! 活跃处理，防止异常状态数据绕过守卫、静默移除最后一个可用 Owner。

use crate::sqlx::PgPool;

use crate::users::{
    ManagementActorCredential,
    domain::{UserId, UserRole, UserStatus},
};

use super::management_actor::{
    ManagementActorRejection, lock_management_user_advisories, lock_management_user_rows,
    validate_management_actor,
};

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
/// 终局显式化后，调用方 match 时由编译器保证覆盖完整，不存在兜底分支。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerGuardOutcome {
    /// 写入已提交。
    Updated,
    /// 目标用户不存在。
    NotFound,
    /// 拒绝：这是最后一个活跃 Owner。
    LastOwnerRequired,
    /// 拒绝：现有或请求角色需要 `ManageRoles`，但 actor 只有 `ManageUsers`。
    ManageRolesRequired,
    /// 拒绝：用户 Session 的状态或 generation 已在初始授权后变化。
    ActorSessionInvalid,
    /// 拒绝：事务内锁定的 actor 角色不再具备 `ManageUsers`。
    ActorPermissionRequired,
}

/// Lock every active Owner row in primary-key order and return the invariant count.
///
/// The caller has already acquired actor/target advisory locks and locks their rows only after
/// this function. Keeping that three-stage order identical for role and status writes prevents
/// both the last-Owner race and actor/target row-lock inversion.
async fn lock_active_owner_scope(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
) -> Result<usize, crate::sqlx::Error> {
    // The SQL predicate must remain aligned with `UserStatus::is_active` (Issue #358): any
    // non-disabled value counts as active so malformed future data cannot remove the final Owner.
    let active_owners: Vec<(UserId,)> = crate::sqlx::query_as(
        "SELECT id FROM users WHERE role = 'owner' AND status <> 'disabled' ORDER BY id FOR UPDATE",
    )
    .fetch_all(&mut **transaction)
    .await?;
    Ok(active_owners.len())
}

pub async fn set_user_role(
    pool: &PgPool,
    id: UserId,
    role: UserRole,
    credential: ManagementActorCredential,
) -> Result<OwnerGuardOutcome, crate::sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let outcome = match set_user_role_in_transaction(
        &mut transaction,
        id,
        role,
        credential,
        None::<crate::audit::AuditEvent>,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(RoleWriteError::Database(error)) => {
            transaction.rollback().await?;
            return Err(error);
        }
        // 非审计包装层不传入审计回调，这个分支在类型上可达、在运行时不可达。
        Err(RoleWriteError::Audit(error)) => {
            transaction.rollback().await?;
            return Err(crate::sqlx::Error::Protocol(format!(
                "role write audit failed: {error}"
            )));
        }
    };
    // 核心不做回滚；守卫拒绝的终局没有写入，由这里释放事务。
    if outcome != OwnerGuardOutcome::Updated {
        transaction.rollback().await?;
        return Ok(outcome);
    }
    transaction.commit().await?;
    Ok(outcome)
}

#[derive(Debug)]
enum RoleWriteError {
    Database(crate::sqlx::Error),
    Audit(crate::audit::AuditError),
}

impl From<crate::sqlx::Error> for RoleWriteError {
    fn from(error: crate::sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// 角色与审计在同一事务内落地的共享核心：
/// - actor 凭证在事务内锁定并复检（#493）；
/// - 任何角色变化都推进 session_epoch 并撤销全部凭据（#493）；
/// - 目标为特权角色时要求 Owner 权限（#424）；
/// - 提供审计回调时，审计与角色变更原子提交（#474）。
async fn set_user_role_in_transaction(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    id: UserId,
    role: UserRole,
    credential: ManagementActorCredential,
    audit_event: Option<crate::audit::AuditEvent>,
) -> Result<OwnerGuardOutcome, RoleWriteError> {
    let lock_order = lock_management_user_advisories(transaction, id, credential).await?;
    let active_owner_count = lock_active_owner_scope(transaction).await?;
    let locked = lock_management_user_rows(transaction, &lock_order).await?;
    let access = match validate_management_actor(credential, locked.actor.as_ref()) {
        Ok(access) => access,
        Err(rejection) => {
            return Ok(match rejection {
                ManagementActorRejection::SessionInvalid => OwnerGuardOutcome::ActorSessionInvalid,
                ManagementActorRejection::PermissionRequired => {
                    OwnerGuardOutcome::ActorPermissionRequired
                }
            });
        }
    };
    let Some(current) = locked.target else {
        return Ok(OwnerGuardOutcome::NotFound);
    };
    if (UserRole::parse(&current.role).is_some_and(UserRole::is_privileged) || role.is_privileged())
        && !access.permits_owner()
    {
        return Ok(OwnerGuardOutcome::ManageRolesRequired);
    }
    if current.role == "owner"
        && role != UserRole::Owner
        && UserStatus::is_active(&current.status)
        && active_owner_count <= 1
    {
        return Ok(OwnerGuardOutcome::LastOwnerRequired);
    }
    if current.role != role.as_str() {
        // Every role transition is a credential boundary. Revocation advances session_epoch,
        // marks durable Cookie sessions revoked, and makes all Refresh Tokens stamped with the
        // previous epoch fail their redemption check. This also prevents a user->admin/owner
        // transition from passively upgrading an already-issued Session (Issue #493).
        crate::sessions::store::revoke_all_for_user_in_transaction(transaction, id).await?;
        crate::sqlx::query("UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(role.as_str())
            .execute(&mut **transaction)
            .await?;
    }
    if let Some(audit_event) = audit_event {
        crate::audit::repository::insert_with(&mut **transaction, &audit_event)
            .await
            .map_err(RoleWriteError::Audit)?;
    }
    Ok(OwnerGuardOutcome::Updated)
}

#[derive(Debug, thiserror::Error)]
pub enum AuditedRoleGuardError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("audit operation failed: {0}")]
    Audit(#[from] crate::audit::AuditError),
}

/// Role changes are privilege changes, so persist the audit event before the
/// transaction commits. An audit outage therefore rolls the role change back
/// instead of creating an untraceable administrator (#474).
pub async fn set_user_role_with_audit(
    pool: &PgPool,
    id: UserId,
    role: UserRole,
    credential: ManagementActorCredential,
    audit_event: crate::audit::AuditEvent,
) -> Result<OwnerGuardOutcome, AuditedRoleGuardError> {
    let mut transaction = pool.begin().await?;
    let outcome = match set_user_role_in_transaction(
        &mut transaction,
        id,
        role,
        credential,
        Some(audit_event),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(RoleWriteError::Database(error)) => {
            transaction.rollback().await?;
            return Err(AuditedRoleGuardError::Database(error));
        }
        Err(RoleWriteError::Audit(error)) => {
            transaction.rollback().await?;
            return Err(AuditedRoleGuardError::Audit(error));
        }
    };
    if outcome != OwnerGuardOutcome::Updated {
        transaction.rollback().await?;
        return Ok(outcome);
    }
    transaction.commit().await?;
    Ok(outcome)
}

/// 变更用户状态。
///
/// 入参是已解析的 [`UserStatus`]，因此本函数不存在「状态串非法」这一终局 ——
/// 非法输入在 HTTP 层就被拒为 400，不会走到仓储层（Issue #283）。
pub async fn set_user_status_guarded(
    pool: &PgPool,
    id: UserId,
    status: UserStatus,
    credential: ManagementActorCredential,
) -> Result<OwnerGuardOutcome, crate::sqlx::Error> {
    set_user_status_guarded_inner(pool, id, status, credential, None)
        .await
        .map_err(|error| match error {
            StatusWriteError::Database(error) => error,
            StatusWriteError::Audit(_) => {
                unreachable!("unaudited status mutation cannot produce an audit error")
            }
        })
}

pub async fn set_user_status_guarded_with_audit(
    pool: &PgPool,
    id: UserId,
    status: UserStatus,
    credential: ManagementActorCredential,
    audit_event: crate::audit::AuditEvent,
) -> Result<OwnerGuardOutcome, AuditedStatusGuardError> {
    let mut transaction = pool.begin().await?;
    let outcome =
        set_user_status_in_transaction(&mut transaction, id, status, credential, Some(audit_event))
            .await
            .map_err(|error| match error {
                StatusWriteError::Database(error) => AuditedStatusGuardError::Database(error),
                StatusWriteError::Audit(error) => AuditedStatusGuardError::Audit(error),
            })?;
    if outcome == OwnerGuardOutcome::Updated {
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    Ok(outcome)
}

#[derive(Debug, thiserror::Error)]
pub enum AuditedStatusGuardError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("audit operation failed: {0}")]
    Audit(#[from] crate::audit::AuditError),
}

type StatusWriteResult = Result<OwnerGuardOutcome, StatusWriteError>;

#[derive(Debug)]
enum StatusWriteError {
    Database(crate::sqlx::Error),
    Audit(crate::audit::AuditError),
}

impl From<crate::sqlx::Error> for StatusWriteError {
    fn from(error: crate::sqlx::Error) -> Self {
        Self::Database(error)
    }
}

async fn set_user_status_guarded_inner(
    pool: &PgPool,
    id: UserId,
    status: UserStatus,
    credential: ManagementActorCredential,
    audit_event: Option<crate::audit::AuditEvent>,
) -> StatusWriteResult {
    let mut transaction = pool.begin().await?;
    let outcome =
        set_user_status_in_transaction(&mut transaction, id, status, credential, audit_event)
            .await?;
    if outcome == OwnerGuardOutcome::Updated {
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    Ok(outcome)
}

async fn set_user_status_in_transaction(
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    id: UserId,
    status: UserStatus,
    credential: ManagementActorCredential,
    audit_event: Option<crate::audit::AuditEvent>,
) -> StatusWriteResult {
    let lock_order = lock_management_user_advisories(transaction, id, credential).await?;
    let active_owner_count = lock_active_owner_scope(transaction).await?;
    let locked = lock_management_user_rows(transaction, &lock_order).await?;
    let access = match validate_management_actor(credential, locked.actor.as_ref()) {
        Ok(access) => access,
        Err(ManagementActorRejection::SessionInvalid) => {
            return Ok(OwnerGuardOutcome::ActorSessionInvalid);
        }
        Err(ManagementActorRejection::PermissionRequired) => {
            return Ok(OwnerGuardOutcome::ActorPermissionRequired);
        }
    };
    let Some(current) = locked.target else {
        return Ok(OwnerGuardOutcome::NotFound);
    };
    if UserRole::parse(&current.role).is_some_and(UserRole::is_privileged)
        && !access.permits_owner()
    {
        return Ok(OwnerGuardOutcome::ManageRolesRequired);
    }
    if current.role == "owner"
        && UserStatus::is_active(&current.status)
        && status == UserStatus::Disabled
        && active_owner_count <= 1
    {
        return Ok(OwnerGuardOutcome::LastOwnerRequired);
    }
    if UserStatus::parse(&current.status) != Some(status) && status == UserStatus::Disabled {
        crate::sessions::store::revoke_all_for_user_in_transaction(transaction, id).await?;
    }
    let result =
        crate::sqlx::query("UPDATE users SET status = $2, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(status.as_str())
            .execute(&mut **transaction)
            .await?;
    if result.rows_affected() == 1 {
        if let Some(event) = audit_event {
            crate::audit::repository::insert_with(&mut **transaction, &event)
                .await
                .map_err(StatusWriteError::Audit)?;
        }
        Ok(OwnerGuardOutcome::Updated)
    } else {
        Ok(OwnerGuardOutcome::NotFound)
    }
}
