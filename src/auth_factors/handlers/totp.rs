use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

use super::{
    inputs::{TotpConfirmInput, TotpLoginInput, TotpSetupInput, TotpSetupResponse},
    responses::{factor_error_response, totp_confirmation_response},
    ticket_proof::ticket_proof,
};
use crate::{auth_factors::service::TotpConfirmation, error, state::AppState};

pub async fn start_totp_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TotpSetupInput>,
) -> Response {
    let Some((ticket_id, holder_hash)) = ticket_proof(
        &headers,
        input.login_ticket.as_deref(),
        state.config.cookie_secure,
    ) else {
        return error::bad_request("invalid_login_ticket", "login ticket is invalid");
    };
    let Some(user_id) = (match state
        .factors
        .user_id_for_ticket(&ticket_id, &holder_hash)
        .await
    {
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
        .start_totp_enrollment(&ticket_id, &holder_hash, &profile.email, "Chenxing Pass")
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
    let Some((ticket_id, holder_hash)) = ticket_proof(
        &headers,
        input.login_ticket.as_deref(),
        state.config.cookie_secure,
    ) else {
        return error::bad_request("invalid_login_ticket", "login ticket is invalid");
    };
    match state
        .factors
        .confirm_totp_enrollment(&ticket_id, &holder_hash, source_ip.as_deref(), &input.code)
        .await
    {
        // 注册确认端点不承担登录语义：没有待确认的注册就是无效 ticket。
        Ok(confirmation) => {
            totp_confirmation_response(&state, confirmation, &headers, source_ip.as_deref()).await
        }
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
    let Some((ticket_id, holder_hash)) = ticket_proof(
        &headers,
        input.login_ticket.as_deref(),
        state.config.cookie_secure,
    ) else {
        return error::bad_request("invalid_login_ticket", "login ticket is invalid");
    };
    let confirmation = match state
        .factors
        .confirm_totp_enrollment(&ticket_id, &holder_hash, source_ip.as_deref(), &input.code)
        .await
    {
        Ok(TotpConfirmation::NoPendingEnrollment) => match state
            .factors
            .verify_totp_login(&ticket_id, &holder_hash, source_ip.as_deref(), &input.code)
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
    totp_confirmation_response(&state, confirmation, &headers, source_ip.as_deref()).await
}
