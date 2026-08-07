use axum::{
    http::HeaderMap,
    response::Response,
};

use super::super::{
    service::{AuthFactorServiceError, PasskeyConfirmation, TotpConfirmation},
    session::issue_user_session,
};
use crate::{audit::AuditEvent, error, state::AppState, users::domain::UserId};

/// TOTP 确认结果映射：成功签发会话，失败记录审计并返回统一错误。
pub(super) async fn totp_confirmation_response(
    state: &AppState,
    confirmation: TotpConfirmation,
    headers: &HeaderMap,
    source_ip: Option<&str>,
) -> Response {
    match confirmation {
        TotpConfirmation::Completed(user_id) => {
            issue_user_session(state, user_id, "totp", headers).await
        }
        TotpConfirmation::InvalidCode => {
            mfa_failure_response(state, None, "totp_invalid", source_ip).await
        }
        TotpConfirmation::RateLimited => {
            mfa_failure_response(state, None, "totp_rate_limited", source_ip).await
        }
        // `NoPendingEnrollment` 只在登录端点的回落判断逻辑里出现，不会传到这里。
        // 注册确认端点把它当 `InvalidTicket` 处理。
        TotpConfirmation::NoPendingEnrollment | TotpConfirmation::InvalidTicket => {
            error::bad_request("invalid_login_ticket", "login ticket is invalid")
        }
    }
}

/// Passkey 确认结果映射：成功签发会话，失败记录审计并返回统一错误。
pub(super) async fn passkey_confirmation_response(
    state: &AppState,
    confirmation: PasskeyConfirmation,
    headers: &HeaderMap,
    source_ip: Option<&str>,
) -> Response {
    match confirmation {
        PasskeyConfirmation::Completed(user_id) => {
            issue_user_session(state, user_id, "passkey", headers).await
        }
        PasskeyConfirmation::InvalidCredential(user_id) => {
            mfa_failure_response(state, Some(user_id), "passkey_invalid", source_ip).await
        }
        PasskeyConfirmation::RateLimited(user_id) => {
            mfa_failure_response(state, Some(user_id), "passkey_rate_limited", source_ip).await
        }
        PasskeyConfirmation::InvalidTicket => {
            error::bad_request("invalid_login_ticket", "login ticket is invalid")
        }
    }
}

/// 认证因子失败响应：记录审计事件，返回统一的未授权错误。拒绝结果不依赖
/// 审计数据库可用性；写入失败由 AuditService 通过结构化日志暴露。
pub(super) async fn mfa_failure_response(
    state: &AppState,
    actor_id: Option<UserId>,
    reason: &str,
    source_ip: Option<&str>,
) -> Response {
    record_mfa_event(state, actor_id, reason, source_ip).await;
    error::unauthorized("invalid_factor", "authentication factor is invalid")
}

/// 因子服务层错误映射：限流归并到认证失败，其他错误记日志后返回通用 500。
pub(super) fn factor_error_response(
    factor_error: AuthFactorServiceError,
    context: &str,
) -> Response {
    if matches!(factor_error, AuthFactorServiceError::RateLimited) {
        return error::unauthorized("invalid_factor", "authentication factor is invalid");
    }
    tracing::error!(error = %factor_error, context, "factor service error");
    error::internal()
}

/// 认证失败审计事件。限流路径已经从 login ticket 解析出用户，因此可以记录真实
/// actor_id；ticket 值和凭据字节属于凭据材料，不写入审计。
async fn record_mfa_event(
    state: &AppState,
    actor_id: Option<UserId>,
    reason: &str,
    source_ip: Option<&str>,
) {
    state
        .audit
        .record_best_effort(AuditEvent::authentication_failure(
            "mfa_failure".to_owned(),
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "anonymous".to_owned()
            },
            actor_id.map(|id| id.to_string()),
            "authentication_factor".to_owned(),
            None,
            reason,
            None,
            source_ip,
        ))
        .await;
}
