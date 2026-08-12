use axum::response::Response;

use super::domain::AdminPermission;
use crate::{
    api::extract::AdminWrite,
    audit::AuditEvent,
    error,
    state::AppState,
    users::domain::{UserId, UserRole},
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

/// 校验一个「以某个用户为目标」的管理写操作。
///
/// # 为什么授权必须先于资源查询（Issue #280）
///
/// 旧实现先查目标用户的角色，再据此决定需要 `ManageUsers` 还是 `ManageRoles`。
/// 这让权限门槛成为资源状态的函数：任何能触达端点的调用者都会先触发一次数据库
/// 查询，并从「403 说的是哪个权限」里读出目标用户是否存在、是否是 Owner。
/// 权限检查本身变成了资源存在性预言机（existence oracle）。
///
/// 现在顺序固定为三步，且第一步与目标无关：
///
/// 1. 调用方先按与目标无关的基线权限（`ManageUsers`）授权。不具备基线权限的调用者
///    在任何查询之前就被拒，拿不到任何与目标有关的信号。
/// 2. 本函数查询目标用户。不存在即 404 —— 此时调用者已经具备基线权限，
///    而基线权限本身就允许列出用户与管理员，404 不泄露新信息。
/// 3. 目标是 Owner 时把门槛抬到 `ManageRoles`。Owner 保护类操作
///    （禁用 Owner、改写 Owner 的套餐）统一走这一档，不因入口而漂移。
///
/// `actor` 参数是第 1 步已经完成的凭证：`AdminActor` 只能从
/// [`AdminWrite::authorize`] 取得，因此调用方无法跳过基线授权直接调用本函数。
/// 返回的 `AdminActor` 对应最终生效的那一档权限。
pub(crate) async fn authorize_user_write(
    state: &AppState,
    admin: &AdminWrite,
    actor: AdminActor,
    user_id: UserId,
) -> Result<AdminActor, Response> {
    let profile = match state.users.find_profile(user_id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return Err(error::not_found("user_not_found", "user was not found")),
        Err(error_value) => {
            tracing::error!(
                error = %error_value,
                "failed to load the target user before an admin write"
            );
            return Err(error::internal());
        }
    };
    if profile.role != UserRole::Owner {
        return Ok(actor);
    }
    // Owner 的账号状态与权益由角色管理档位把守：只有 ManageUsers 的 Admin
    // 不得通过禁用或改套餐的方式影响最高权限持有者。
    admin.authorize(state, AdminPermission::ManageRoles).await
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
            OWNER_GUARD_DENIED_ACTION.to_owned(),
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
        "admin_authorization_denied".to_owned(),
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
