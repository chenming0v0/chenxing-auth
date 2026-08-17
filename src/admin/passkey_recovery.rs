//! 管理端 Passkey 恢复接口（#460）。
//!
//! Passkey-only 账号丢了全部认证器之后没有自助出口：登录要现有 Passkey，
//! 管理 Session 也要先登录。末位 Owner 会把自己锁死。本模块提供受控重置：
//!
//! - `DELETE /api/v1/admin/users/{user_id}/auth-factors/passkey`
//!
//! 授权是 Owner 专属的 `ManageAuthFactors`，或系统 `ADMIN_TOKEN`（权限等价
//! Owner，无用户 ID，豁免 CSRF）。后者不依赖任何用户 Session / Passkey，
//! 是末位 Owner 的逃生通道，不能形成需要现有凭据的闭环。
//!
//! 响应不返回 credential_id、公钥或 counter。

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use super::{
    authorization::{authorize_admin_write, management_actor_validation_failed},
    domain::AdminPermission,
};
use crate::{
    api::extract::AdminWrite,
    audit::AuditEvent,
    auth_factors::service::{AuthFactorServiceError, PasskeyResetOutcome},
    error,
    state::AppState,
    users::domain::UserId,
};

#[derive(Debug, Serialize)]
pub struct PasskeyResetResponse {
    user_id: UserId,
    /// 本次清掉的 Passkey 凭据条数。
    removed: i64,
    /// 重置同时撤销了该账号的全部会话与已签发 Refresh Token（`session_epoch`
    /// 被推进，两者在同一水位上一起失效，Issue #409），固定为 true。
    credentials_revoked: bool,
}

/// 重置某个账号的全部 Passkey 凭据。
///
/// 权限是 Owner 专属的 `ManageAuthFactors`，而不是 `ManageUsers`：这个动作把
/// Passkey-only 账号降级为「只有密码」，下次密码登录可签发普通 Session，再从
/// 安全设置注册新因素。它是账号接管链条上的一环，必须与普通用户管理分权。
///
/// 末位 Owner 丢失全部 Passkey 时无法签发新的管理 Session。系统 Token 通道
/// 不读用户 Session、不验 Passkey，是这条恢复路径唯一不形成闭环的入口。
///
/// 撤销会话与删除凭据由 `AuthFactorService::reset_passkey_factor` 在同一事务
/// 内原子完成：`Missing`/`UnknownUser` 时整体回滚，不会留下「会话已撤、凭据
/// 未删」的中间态。`revoke_all_for_user_in_transaction` 推进该用户的
/// `session_epoch`：Cookie 会话与全部已签发 Refresh Token 在同一水位上一起
/// 失效（Issue #409）。
pub async fn reset_user_passkey_factor(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(user_id): Path<UserId>,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageAuthFactors).await {
            Ok(authorization) => authorization,
            Err(response) => return response,
        };
    let outcome = match state
        .factors
        .reset_passkey_factor(user_id, authorization.credential())
        .await
    {
        Ok(outcome) => outcome,
        Err(AuthFactorServiceError::ManagementActor(error_value)) => {
            return management_actor_validation_failed(&state, authorization, error_value).await;
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to reset Passkey factor");
            return error::internal();
        }
    };
    let removed = match outcome {
        PasskeyResetOutcome::Removed { removed } => removed,
        PasskeyResetOutcome::Missing => {
            return error::not_found("passkey_factor_not_found", "Passkey factor was not found");
        }
        PasskeyResetOutcome::UnknownUser => {
            return error::not_found("user_not_found", "user was not found");
        }
    };
    let (actor_type, actor_id) = authorization.actor().audit_fields();
    // 凭据已经删除，这个既成事实不因审计写入失败而改写。元数据只含条数，
    // 不含 credential_id、公钥或 counter。
    state
        .audit
        .record_best_effort(AuditEvent::new(
            actor_type.to_owned(),
            actor_id,
            crate::audit::AuditAction::UserPasskeyFactorReset,
            "authentication_factor".to_owned(),
            Some(user_id.to_string()),
            serde_json::json!({
                "result": "success",
                "method": "passkey",
                "removed": removed,
                "credentials_revoked": true,
            }),
        ))
        .await;
    (
        StatusCode::OK,
        Json(PasskeyResetResponse {
            user_id,
            removed,
            credentials_revoked: true,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::PasskeyResetResponse;

    #[test]
    fn reset_response_reports_count_and_revocation_without_credential_material() {
        let value = serde_json::to_value(PasskeyResetResponse {
            user_id: 7,
            removed: 2,
            credentials_revoked: true,
        })
        .expect("reset response serializes");

        assert_eq!(value["removed"], 2);
        assert_eq!(value["credentials_revoked"], true);
        assert!(value.get("credential_id").is_none());
        assert!(value.get("credential").is_none());
        assert!(value.get("public_key").is_none());
        assert!(value.get("counter").is_none());
    }
}
