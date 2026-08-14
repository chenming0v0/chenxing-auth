use axum::response::Response;

use super::domain::AdminPermission;
use crate::{
    api::extract::AdminWrite,
    audit::AuditEvent,
    error,
    state::AppState,
    users::domain::{OwnerTargetAccess, UserId},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminActor {
    User(UserId),
    SystemToken,
}

impl AdminActor {
    pub const fn actor_type(self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::SystemToken => "system_token",
        }
    }

    pub fn user_id(self) -> Option<UserId> {
        match self {
            Self::User(user_id) => Some(user_id),
            Self::SystemToken => None,
        }
    }

    pub fn audit_fields(self) -> (&'static str, Option<String>) {
        (self.actor_type(), self.user_id().map(|id| id.to_string()))
    }
}

/// 已通过目标无关的 `ManageUsers` 基线授权及其最高写入档位。
///
/// 这里只携带调用者能力，不查询目标用户。目标是否为 Owner 由具体写事务持行锁判定，
/// 因而这个值可以安全地跨越输入解析，但不能代替仓储层的目标角色检查（Issue #323）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserWriteAuthorization {
    actor: AdminActor,
    access: OwnerTargetAccess,
}

impl UserWriteAuthorization {
    pub const fn actor(self) -> AdminActor {
        self.actor
    }

    pub const fn access(self) -> OwnerTargetAccess {
        self.access
    }
}

pub(crate) async fn authorize_user_write(
    state: &AppState,
    admin: &AdminWrite,
) -> Result<UserWriteAuthorization, Response> {
    let actor = admin.authorize(state, AdminPermission::ManageUsers).await?;
    Ok(UserWriteAuthorization {
        actor,
        access: admin.owner_target_access(),
    })
}

/// 把事务内判定出的 Owner 权限不足翻译成既有的 403 与拒绝审计。
///
/// 目标角色不能再由 HTTP 层预读：预读与写入之间可以并发晋升为 Owner（Issue #323）。
/// 状态/套餐仓储在锁住目标行后返回 `ManageRolesRequired`，写事务已经回滚；这里仅恢复
/// Issue #280 确立的外部语义，不再查询目标，也不重试写入。
pub(crate) async fn owner_write_permission_denied(
    state: &AppState,
    authorization: UserWriteAuthorization,
) -> Response {
    let actor = authorization.actor();
    if authorization.access().permits_owner() {
        tracing::error!(
            actor_type = actor.actor_type(),
            actor_id = ?actor.user_id(),
            "owner write was rejected despite a ManageRoles capability"
        );
        return error::internal();
    }
    if let Some(user_id) = actor.user_id() {
        record_authz_denial(
            state,
            user_id,
            AdminPermission::ManageRoles,
            "insufficient_role",
        )
        .await;
    }
    error::forbidden(
        "admin_forbidden",
        "administrator permission is insufficient",
    )
}

/// 领域守卫拒绝一个管理写操作时的审计 action。
///
/// 与 `admin_authorization_denied` 分开：那个表示「调用者权限不够」，这个表示
/// 「调用者权限足够，但操作会破坏系统不变量」。混用一个 action 会让审计查询
/// 无法区分「有人在越权探测」和「管理员正试图移除最后一个 Owner」。
pub const OWNER_GUARD_DENIED_ACTION: &str = "admin_owner_guard_denied";

/// 受 Owner 守卫保护的管理写操作，用于审计里的 `operation` 字段。
///
/// 用枚举而不是字符串字面量：新增受守卫保护的端点时，编译器会要求在这里登记
/// 一个稳定的可检索名字，而不是让每个 handler 各自拼一个措辞。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerGuardedOperation {
    /// `POST /api/v1/admin/users/{id}/{status}`
    UserStatusUpdate,
    /// `POST /api/v1/admin/users/{id}/role`
    UserRoleUpdate,
}

impl OwnerGuardedOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserStatusUpdate => "user_status_update",
            Self::UserRoleUpdate => "user_role_update",
        }
    }
}

/// 记录一次被 Owner 守卫拒绝的管理写操作（Issue #304）。
///
/// # 为什么这条拒绝必须留痕
///
/// 「系统必须保留至少一个活跃 Owner」是领域不变量，命中它的请求来自具备
/// `ManageUsers` / `ManageRoles` 的调用者 —— 也就是说，这是一个**有权限的**
/// 主体正在试图移除管理面的最高权限持有者。无论它是操作失误还是接管企图，
/// 都属于安全相关决策，此前却只返回 409，审计表里没有任何记录。
///
/// 记录的四个事实与 issue 要求一一对应：
///
/// - actor：`actor_type` + `actor_id`，取自 [`AdminActor`]，系统 Token 无用户 id。
/// - target：`resource_type = "user"` + 目标用户 id。
/// - operation：元数据 `operation`，取自 [`OwnerGuardedOperation`]。
/// - reason：元数据 `reason = "last_owner_required"`，与 HTTP 错误码同名。
///
/// 元数据额外带上 `requested`（目标状态或目标角色）。它是与资源无关的枚举值，
/// 不含用户输入的自由文本，因此可以安全入库；口令、令牌、Cookie 和请求体
/// 其余部分都不进审计。
///
/// 策略与其他拒绝路径一致 —— best-effort：请求已经被拒且不签发任何凭据，
/// 审计写入失败不改写这个结果，只通过 `audit.best_effort_failure` 留痕。
pub(crate) async fn record_owner_guard_denial(
    state: &AppState,
    actor: AdminActor,
    target_user_id: UserId,
    operation: OwnerGuardedOperation,
    requested: &str,
) {
    let (actor_type, actor_id) = actor.audit_fields();
    state
        .audit
        .record_best_effort(AuditEvent::new(
            actor_type.to_owned(),
            actor_id,
            crate::audit::AuditAction::AdminOwnerGuardDenied,
            "user".to_owned(),
            Some(target_user_id.to_string()),
            serde_json::json!({
                "result": "failure",
                "reason": "last_owner_required",
                "operation": operation.as_str(),
                "requested": requested,
            }),
        ))
        .await;
}

/// 以 best-effort 方式将授权失败写入审计日志。
///
/// 这是**拒绝路径**——请求已经被拒，不签发任何凭据。
/// 若审计写入失败，仍然返回 403/400，不将写入失败暴露给调用方：
/// - 把写入错误改成 500 会向探测者透露额外信息，且无助于安全决策。
/// - 写入失败时通过 `tracing::error!` 保留可检索的结构化上下文，
///   供运维人工补录或告警。
///
/// 凭据签发路径（client_create / client_secret_rotate）使用阻断式审计——
/// 两种策略的选择依据见 `audit` 模块文档。
pub(crate) async fn record_authz_denial(
    state: &AppState,
    user_id: UserId,
    permission: AdminPermission,
    reason: &'static str,
) {
    // AdminPermission 无 as_str()，Debug 输出（如 `ManageUsers`）作为稳定的可检索标识。
    let permission = format!("{permission:?}");
    let event = AuditEvent::security_failure(
        crate::audit::AuditAction::AdminAuthorizationDenied,
        // 走到这里说明 current_user 已认证成功，actor_type 固定为 "user"
        "user".to_owned(),
        Some(user_id.to_string()),
        "admin_permission".to_owned(),
        Some(permission.clone()),
        reason,
    );
    // 绑定名不用 `error`：本模块已导入 `crate::error`，同名局部变量会掩盖它。
    if let Err(error_value) = state.audit.record(event).await {
        // 不上升为 500；审计写入失败不改变已经确定的拒绝结果
        tracing::error!(
            event = "audit.authorization_denial_unrecorded",
            actor_id = %user_id,
            permission = %permission,
            reason,
            error = %error_value,
            "best-effort 授权失败审计写入失败，事件未入库"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue #304：`operation` 是审计查询用的稳定标识，不能随手改措辞。
    ///
    /// 与成功事件的 action 命名保持同族（`user_role_update` 已是角色变更成功事件的
    /// action），运维因此可以用同一个词把「改成功了」和「被守卫拒了」拉到一起看。
    #[test]
    fn guarded_operation_names_are_stable_and_distinct() {
        assert_eq!(
            OwnerGuardedOperation::UserStatusUpdate.as_str(),
            "user_status_update"
        );
        assert_eq!(
            OwnerGuardedOperation::UserRoleUpdate.as_str(),
            "user_role_update"
        );
        assert_ne!(
            OwnerGuardedOperation::UserStatusUpdate.as_str(),
            OwnerGuardedOperation::UserRoleUpdate.as_str()
        );
    }

    /// 守卫拒绝与权限拒绝必须是两个 action：前者是"有权限但违反不变量"，
    /// 后者是"权限不足"。合并会让审计查询分不清越权探测与 Owner 移除企图。
    #[test]
    fn owner_guard_denial_action_is_separate_from_permission_denial() {
        assert_eq!(OWNER_GUARD_DENIED_ACTION, "admin_owner_guard_denied");
        assert_ne!(OWNER_GUARD_DENIED_ACTION, "admin_authorization_denied");
    }

    /// 系统 Token 没有用户 id，审计字段必须如实反映这一点而不是伪造一个 actor。
    #[test]
    fn system_token_actor_records_no_user_id() {
        assert_eq!(
            AdminActor::SystemToken.audit_fields(),
            ("system_token", None)
        );
        assert_eq!(
            AdminActor::User(7).audit_fields(),
            ("user", Some("7".to_owned()))
        );
    }
}
