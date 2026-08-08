use super::domain::AdminPermission;
use crate::{audit::AuditEvent, state::AppState, users::domain::UserId};

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
    if let Err(error) = state.audit.record(event).await {
        // 不上升为 500；审计写入失败不改变已经确定的拒绝结果
        tracing::error!(
            event = "audit.authorization_denial_unrecorded",
            actor_id = %user_id,
            permission = %permission,
            reason,
            error = %error,
            "best-effort 授权失败审计写入失败，事件未入库"
        );
    }
}
