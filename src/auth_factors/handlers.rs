use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use super::{
    service::{AuthFactorServiceError, PasskeyConfirmation, TotpConfirmation},
    session::issue_user_session,
};
use crate::{audit::AuditEvent, error, state::AppState, users::domain::UserId};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

#[derive(Debug, Deserialize)]
pub struct TotpSetupInput {
    pub login_ticket: String,
}

#[derive(Debug, Serialize)]
struct TotpSetupResponse<'a> {
    secret_base32: &'a str,
    otpauth_url: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct TotpConfirmInput {
    pub login_ticket: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpLoginInput {
    pub login_ticket: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyTicketInput {
    pub login_ticket: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegistrationInput {
    pub login_ticket: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyAuthenticationInput {
    pub login_ticket: String,
    pub credential: PublicKeyCredential,
}

pub async fn start_totp_setup(
    State(state): State<AppState>,
    Json(input): Json<TotpSetupInput>,
) -> Response {
    let Some(user_id) = (match state.factors.user_id_for_ticket(&input.login_ticket).await {
        Ok(user_id) => user_id,
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to load TOTP ticket");
            return error::internal();
        }
    }) else {
        return error::bad_request("invalid_login_ticket", "login ticket is invalid");
    };
    let Some(profile) = (match state.users.find_profile(user_id).await {
        Ok(profile) => profile,
        Err(user_error) => {
            tracing::error!(error = %user_error, "failed to load TOTP account");
            return error::internal();
        }
    }) else {
        return error::bad_request("invalid_login_ticket", "login ticket is invalid");
    };
    let ticket = match state
        .factors
        .start_totp_enrollment(&input.login_ticket, &profile.email, "Chenxing Pass")
        .await
    {
        Ok(ticket) => ticket,
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to start TOTP enrollment");
            return error::internal();
        }
    };
    let Some(ticket) = ticket else {
        return error::bad_request("invalid_login_ticket", "login ticket is invalid");
    };
    (
        axum::http::StatusCode::OK,
        Json(TotpSetupResponse {
            secret_base32: ticket.secret_base32(),
            otpauth_url: ticket.otpauth_url(),
        }),
    )
        .into_response()
}

pub async fn confirm_totp_setup(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<TotpConfirmInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    match state
        .factors
        .confirm_totp_enrollment(&input.login_ticket, source_ip.as_deref(), &input.code)
        .await
    {
        // 注册确认端点不承担登录语义：没有待确认的注册就是无效 ticket。
        Ok(confirmation) => totp_confirmation_response(&state, confirmation, &headers).await,
        Err(factor_error) => factor_error_response(factor_error, "confirm TOTP enrollment"),
    }
}

/// 登录端点。先看这张 ticket 上有没有待确认的 TOTP 注册：有就完成注册并签发会话，
/// 没有才回落到已注册因子的验证。
///
/// 回落判断依据 `NoPendingEnrollment` 而不是 `InvalidTicket`：后者同时表达「ticket
/// 无效」和「无待确认注册」时，无法区分这两种情况，只能盲目重试第二个 service 方法，
/// 让同一次请求走两轮 `reserve` + `release`（#116）。`NoPendingEnrollment` 在预留额度
/// 之前返回，因此一次请求只消耗一轮限流额度。
pub async fn login_totp(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<TotpLoginInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let confirmation = match state
        .factors
        .confirm_totp_enrollment(&input.login_ticket, source_ip.as_deref(), &input.code)
        .await
    {
        Ok(TotpConfirmation::NoPendingEnrollment) => match state
            .factors
            .verify_totp_login(&input.login_ticket, source_ip.as_deref(), &input.code)
            .await
        {
            Ok(confirmation) => confirmation,
            Err(factor_error) => return factor_error_response(factor_error, "verify TOTP login"),
        },
        Ok(confirmation) => confirmation,
        Err(factor_error) => {
            return factor_error_response(factor_error, "confirm TOTP enrollment login");
        }
    };
    totp_confirmation_response(&state, confirmation, &headers).await
}

pub async fn start_passkey_registration(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<PasskeyTicketInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let Some(user_id) = (match state.factors.user_id_for_ticket(&input.login_ticket).await {
        Ok(user_id) => user_id,
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to load passkey ticket");
            return error::internal();
        }
    }) else {
        return error::bad_request("invalid_login_ticket", "login ticket is invalid");
    };
    let Some(profile) = (match state.users.find_profile(user_id).await {
        Ok(profile) => profile,
        Err(user_error) => {
            tracing::error!(error = %user_error, "failed to load passkey account");
            return error::internal();
        }
    }) else {
        return error::bad_request("invalid_login_ticket", "login ticket is invalid");
    };
    match state
        .factors
        .start_passkey_registration(
            &input.login_ticket,
            source_ip.as_deref(),
            &profile.email,
            profile.display_name.as_deref().unwrap_or(&profile.username),
        )
        .await
    {
        Ok(Some(challenge)) => (axum::http::StatusCode::OK, Json(challenge)).into_response(),
        Ok(None) => error::bad_request("invalid_login_ticket", "login ticket is invalid"),
        Err(AuthFactorServiceError::PasskeyDisabled) => {
            error::bad_request("passkey_disabled", "passkey authentication is disabled")
        }
        Err(AuthFactorServiceError::RateLimited) => {
            mfa_failure_response(&state, Some(user_id), "passkey_rate_limited").await
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to start passkey registration");
            error::internal()
        }
    }
}

pub async fn finish_passkey_registration(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<PasskeyRegistrationInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    match state
        .factors
        .finish_passkey_registration(&input.login_ticket, source_ip.as_deref(), &input.credential)
        .await
    {
        Ok(confirmation) => passkey_confirmation_response(&state, confirmation, &headers).await,
        Err(AuthFactorServiceError::PasskeyDisabled) => {
            error::bad_request("passkey_disabled", "passkey authentication is disabled")
        }
        // 注册冲突不向调用方区分：凭据已被占用与限流都只回一个通用因子失败。
        Err(AuthFactorServiceError::RateLimited | AuthFactorServiceError::PasskeyConflict) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to finish passkey registration");
            error::internal()
        }
    }
}

pub async fn start_passkey_authentication(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<PasskeyTicketInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    match state
        .factors
        .start_passkey_authentication(&input.login_ticket, source_ip.as_deref())
        .await
    {
        Ok(Some(challenge)) => (axum::http::StatusCode::OK, Json(challenge)).into_response(),
        Ok(None) => error::bad_request("invalid_login_ticket", "login ticket is invalid"),
        Err(AuthFactorServiceError::PasskeyDisabled) => {
            error::bad_request("passkey_disabled", "passkey authentication is disabled")
        }
        Err(AuthFactorServiceError::RateLimited) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to start passkey authentication");
            error::internal()
        }
    }
}

pub async fn finish_passkey_authentication(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<PasskeyAuthenticationInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    match state
        .factors
        .finish_passkey_authentication(&input.login_ticket, source_ip.as_deref(), &input.credential)
        .await
    {
        Ok(confirmation) => passkey_confirmation_response(&state, confirmation, &headers).await,
        Err(AuthFactorServiceError::PasskeyDisabled) => {
            error::bad_request("passkey_disabled", "passkey authentication is disabled")
        }
        Err(AuthFactorServiceError::RateLimited) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to finish passkey authentication");
            error::internal()
        }
    }
}

/// TOTP 确认结果映射：成功签发会话，失败记录审计并返回统一错误。
async fn totp_confirmation_response(
    state: &AppState,
    confirmation: TotpConfirmation,
    headers: &HeaderMap,
) -> Response {
    match confirmation {
        TotpConfirmation::Completed(user_id) => {
            issue_user_session(state, user_id, "totp", headers).await
        }
        TotpConfirmation::InvalidCode => mfa_failure_response(state, None, "totp_invalid").await,
        TotpConfirmation::RateLimited => {
            mfa_failure_response(state, None, "totp_rate_limited").await
        }
        // `NoPendingEnrollment` 只在登录端点的回落判断逻辑里出现，不会传到这里。
        // 注册确认端点把它当 `InvalidTicket` 处理。
        TotpConfirmation::NoPendingEnrollment | TotpConfirmation::InvalidTicket => {
            error::bad_request("invalid_login_ticket", "login ticket is invalid")
        }
    }
}

/// Passkey 确认结果映射：成功签发会话，失败记录审计并返回统一错误。
async fn passkey_confirmation_response(
    state: &AppState,
    confirmation: PasskeyConfirmation,
    headers: &HeaderMap,
) -> Response {
    match confirmation {
        PasskeyConfirmation::Completed(user_id) => {
            issue_user_session(state, user_id, "passkey", headers).await
        }
        PasskeyConfirmation::InvalidCredential(user_id) => {
            mfa_failure_response(state, Some(user_id), "passkey_invalid").await
        }
        PasskeyConfirmation::RateLimited(user_id) => {
            mfa_failure_response(state, Some(user_id), "passkey_rate_limited").await
        }
        PasskeyConfirmation::InvalidTicket => {
            error::bad_request("invalid_login_ticket", "login ticket is invalid")
        }
    }
}

/// 认证因子失败响应：记录审计事件，返回统一的未授权错误。拒绝结果不依赖
/// 审计数据库可用性；写入失败由 AuditService 通过结构化日志暴露。
async fn mfa_failure_response(
    state: &AppState,
    actor_id: Option<UserId>,
    reason: &str,
) -> Response {
    record_mfa_event(state, actor_id, reason).await;
    error::unauthorized("invalid_factor", "authentication factor is invalid")
}

/// 因子服务层错误映射：限流归并到认证失败，其他错误记日志后返回通用 500。
fn factor_error_response(factor_error: AuthFactorServiceError, context: &str) -> Response {
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
) {
    state
        .audit
        .record_best_effort(AuditEvent::new(
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "anonymous".to_owned()
            },
            actor_id.map(|id| id.to_string()),
            "mfa_failure".to_owned(),
            "authentication_factor".to_owned(),
            None,
            serde_json::json!({"reason": reason}),
        ))
        .await;
}
