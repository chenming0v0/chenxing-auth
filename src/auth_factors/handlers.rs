use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use super::{
    service::{PasskeyConfirmation, TotpConfirmation},
    session::issue_user_session,
};
use crate::{error, state::AppState};
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
    Json(input): Json<TotpConfirmInput>,
) -> Response {
    let source_ip = crate::api::source_ip(connect_info.map(|Extension(ConnectInfo(peer))| peer));
    match state
        .factors
        .confirm_totp_enrollment(&input.login_ticket, source_ip.as_deref(), &input.code)
        .await
    {
        Ok(TotpConfirmation::Completed(user_id)) => {
            issue_user_session(&state, user_id, "totp").await
        }
        Ok(TotpConfirmation::InvalidCode) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Ok(TotpConfirmation::RateLimited) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Ok(TotpConfirmation::InvalidTicket) => {
            error::bad_request("invalid_login_ticket", "login ticket is invalid")
        }
        Err(crate::auth_factors::service::AuthFactorServiceError::RateLimited) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to confirm TOTP enrollment");
            error::internal()
        }
    }
}

pub async fn login_totp(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(input): Json<TotpLoginInput>,
) -> Response {
    let source_ip = crate::api::source_ip(connect_info.map(|Extension(ConnectInfo(peer))| peer));
    match state
        .factors
        .confirm_totp_enrollment(&input.login_ticket, source_ip.as_deref(), &input.code)
        .await
    {
        Ok(crate::auth_factors::service::TotpConfirmation::Completed(user_id)) => {
            return issue_user_session(&state, user_id, "totp").await;
        }
        Ok(crate::auth_factors::service::TotpConfirmation::InvalidCode) => {
            return error::unauthorized("invalid_factor", "authentication factor is invalid");
        }
        Ok(crate::auth_factors::service::TotpConfirmation::RateLimited) => {
            return error::unauthorized("invalid_factor", "authentication factor is invalid");
        }
        Ok(crate::auth_factors::service::TotpConfirmation::InvalidTicket) => {}
        Err(crate::auth_factors::service::AuthFactorServiceError::RateLimited) => {
            return error::unauthorized("invalid_factor", "authentication factor is invalid");
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to confirm TOTP enrollment login");
            return error::internal();
        }
    }
    match state
        .factors
        .verify_totp_login(&input.login_ticket, source_ip.as_deref(), &input.code)
        .await
    {
        Ok(crate::auth_factors::service::TotpConfirmation::Completed(user_id)) => {
            issue_user_session(&state, user_id, "totp").await
        }
        Ok(crate::auth_factors::service::TotpConfirmation::InvalidCode) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Ok(crate::auth_factors::service::TotpConfirmation::RateLimited) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Ok(crate::auth_factors::service::TotpConfirmation::InvalidTicket) => {
            error::bad_request("invalid_login_ticket", "login ticket is invalid")
        }
        Err(crate::auth_factors::service::AuthFactorServiceError::RateLimited) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to verify TOTP login");
            error::internal()
        }
    }
}

pub async fn start_passkey_registration(
    State(state): State<AppState>,
    Json(input): Json<PasskeyTicketInput>,
) -> Response {
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
            &profile.email,
            profile.display_name.as_deref().unwrap_or(&profile.username),
        )
        .await
    {
        Ok(Some(challenge)) => (axum::http::StatusCode::OK, Json(challenge)).into_response(),
        Ok(None) => error::bad_request("invalid_login_ticket", "login ticket is invalid"),
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to start passkey registration");
            error::internal()
        }
    }
}

pub async fn finish_passkey_registration(
    State(state): State<AppState>,
    Json(input): Json<PasskeyRegistrationInput>,
) -> Response {
    match state
        .factors
        .finish_passkey_registration(&input.login_ticket, &input.credential)
        .await
    {
        Ok(PasskeyConfirmation::Completed(user_id)) => {
            issue_user_session(&state, user_id, "passkey").await
        }
        Ok(PasskeyConfirmation::InvalidCredential) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Ok(PasskeyConfirmation::InvalidTicket) => {
            error::bad_request("invalid_login_ticket", "login ticket is invalid")
        }
        Err(factor_error) => {
            if matches!(
                &factor_error,
                crate::auth_factors::service::AuthFactorServiceError::RateLimited
                    | crate::auth_factors::service::AuthFactorServiceError::PasskeyConflict
            ) {
                return error::unauthorized("invalid_factor", "authentication factor is invalid");
            }
            tracing::error!(error = %factor_error, "failed to finish passkey registration");
            error::internal()
        }
    }
}

pub async fn start_passkey_authentication(
    State(state): State<AppState>,
    Json(input): Json<PasskeyTicketInput>,
) -> Response {
    match state
        .factors
        .start_passkey_authentication(&input.login_ticket)
        .await
    {
        Ok(Some(challenge)) => (axum::http::StatusCode::OK, Json(challenge)).into_response(),
        Ok(None) => error::bad_request("invalid_login_ticket", "login ticket is invalid"),
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to start passkey authentication");
            error::internal()
        }
    }
}

pub async fn finish_passkey_authentication(
    State(state): State<AppState>,
    Json(input): Json<PasskeyAuthenticationInput>,
) -> Response {
    match state
        .factors
        .finish_passkey_authentication(&input.login_ticket, &input.credential)
        .await
    {
        Ok(PasskeyConfirmation::Completed(user_id)) => {
            issue_user_session(&state, user_id, "passkey").await
        }
        Ok(PasskeyConfirmation::InvalidCredential) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Ok(PasskeyConfirmation::InvalidTicket) => {
            error::bad_request("invalid_login_ticket", "login ticket is invalid")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to finish passkey authentication");
            error::internal()
        }
    }
}
