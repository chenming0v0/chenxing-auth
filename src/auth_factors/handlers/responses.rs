use axum::{http::HeaderMap, response::Response};

use super::super::{
    service::{AuthFactorServiceError, PasskeyConfirmation, TotpConfirmation},
    session::{StaleCredentialCode, issue_user_session},
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
        TotpConfirmation::Completed(authenticated) => {
            issue_user_session(
                state,
                authenticated,
                "totp",
                headers,
                source_ip,
                StaleCredentialCode::InvalidFactor,
                false,
            )
            .await
        }
        TotpConfirmation::InvalidCode => {
            mfa_failure_response(
                state,
                None,
                "totp_invalid",
                source_ip,
                crate::api::user_agent(headers).as_deref(),
            )
            .await
        }
        TotpConfirmation::KeyUnavailable => {
            factor_key_unavailable_response(
                state,
                None,
                source_ip,
                crate::api::user_agent(headers).as_deref(),
            )
            .await
        }
        TotpConfirmation::RateLimited => {
            mfa_failure_response(
                state,
                None,
                "totp_rate_limited",
                source_ip,
                crate::api::user_agent(headers).as_deref(),
            )
            .await
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
        PasskeyConfirmation::Completed(authenticated) => {
            issue_user_session(
                state,
                authenticated,
                "passkey",
                headers,
                source_ip,
                StaleCredentialCode::InvalidFactor,
                false,
            )
            .await
        }
        PasskeyConfirmation::InvalidCredential(user_id) => {
            mfa_failure_response(
                state,
                Some(user_id),
                "passkey_invalid",
                source_ip,
                crate::api::user_agent(headers).as_deref(),
            )
            .await
        }
        PasskeyConfirmation::RateLimited(user_id) => {
            mfa_failure_response(
                state,
                Some(user_id),
                "passkey_rate_limited",
                source_ip,
                crate::api::user_agent(headers).as_deref(),
            )
            .await
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
    user_agent: Option<&str>,
) -> Response {
    record_mfa_event(state, actor_id, reason, source_ip, user_agent).await;
    error::unauthorized("invalid_factor", "authentication factor is invalid")
}

/// 加密 kid 已退役：服务端读不出这份因子（#258）。
///
/// 与 `mfa_failure_response` 分开是三件事的要求：
/// - **语义**：401 `invalid_factor` 是「你的凭据不对」，这里是「服务端的密钥没了」，
///   属于服务端配置状态，所以是 503 `factor_key_unavailable`。用户重试一万次都不会成功，
///   把它伪装成验证码错误只会让用户一直重试到被限流。
/// - **审计**：独立的 action `auth_factor_key_unavailable`，运维可以按它检索出
///   密钥轮换到底锁死了哪些账号，而不是淹没在 `mfa_failure` 里。
/// - **限流**：service 层在这条路径上归还了预留额度且不记账，因此不烧失败额度。
///
/// 走到这里时调用方已经通过了第一因子（密码或有效 login ticket），因此告知
/// 「因子不可用」不构成对未认证者的信息泄漏；反过来，隐瞒它会让用户和客服都
/// 无法判断该找运维还是重新输码。响应不含 kid、种子和密钥环结构。
pub(crate) async fn factor_key_unavailable_response(
    state: &AppState,
    actor_id: Option<UserId>,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) -> Response {
    state
        .audit
        .record_best_effort(AuditEvent::authentication_failure(
            crate::audit::AuditAction::AuthFactorKeyUnavailable,
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "anonymous".to_owned()
            },
            actor_id.map(|id| id.to_string()),
            "authentication_factor".to_owned(),
            None,
            "totp_key_retired",
            None,
            source_ip,
            user_agent,
        ))
        .await;
    error::service_unavailable(
        "factor_key_unavailable",
        "authentication factor cannot be verified; contact an administrator to reset it",
    )
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
    user_agent: Option<&str>,
) {
    state
        .audit
        .record_best_effort(AuditEvent::authentication_failure(
            crate::audit::AuditAction::MfaFailure,
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
            user_agent,
        ))
        .await;
}
