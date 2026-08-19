use super::{
    inputs::{
        DiscoverablePasskeyFinishInput, EmptyInput, PasskeyAuthenticationInput,
        PasskeyRegistrationInput, PasskeyTicketInput,
    },
    responses::{mfa_failure_response, passkey_confirmation_response},
    ticket_proof::ticket_proof,
};
use crate::{
    api::extract::ApiJson,
    auth_factors::{
        service::{AuthFactorServiceError, DiscoverablePasskeyConfirmation},
        session::{StaleCredentialCode, issue_primary_factor_session},
    },
    error,
    state::AppState,
};
use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

#[derive(serde::Serialize)]
struct DiscoverablePasskeyStartResponse {
    challenge_id: String,
    options: webauthn_rs_core::proto::RequestChallengeResponse,
}

pub async fn start_discoverable_passkey_authentication(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    ApiJson(_): ApiJson<EmptyInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    match state
        .factors
        .start_discoverable_passkey_authentication(source_ip.as_deref())
        .await
    {
        Ok(Some((challenge_id, options))) => (
            axum::http::StatusCode::OK,
            Json(DiscoverablePasskeyStartResponse {
                challenge_id,
                options,
            }),
        )
            .into_response(),
        Ok(None) => error::conflict("passkey_operation_pending", "Passkey operation is pending"),
        Err(AuthFactorServiceError::PasskeyDisabled) => {
            error::bad_request("passkey_disabled", "passkey authentication is disabled")
        }
        Err(AuthFactorServiceError::RateLimited) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to start discoverable Passkey authentication");
            error::internal()
        }
    }
}

pub async fn finish_discoverable_passkey_authentication(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<DiscoverablePasskeyFinishInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    match state
        .factors
        .finish_discoverable_passkey_authentication(
            &input.challenge_id,
            source_ip.as_deref(),
            &input.credential,
        )
        .await
    {
        Ok(DiscoverablePasskeyConfirmation::Completed(authenticated)) => {
            issue_primary_factor_session(
                &state,
                authenticated,
                "passkey",
                &headers,
                source_ip.as_deref(),
                StaleCredentialCode::InvalidFactor,
            )
            .await
        }
        Ok(DiscoverablePasskeyConfirmation::Invalid)
        | Ok(DiscoverablePasskeyConfirmation::RateLimited) => {
            error::unauthorized("invalid_passkey", "Passkey authentication is invalid")
        }
        Err(AuthFactorServiceError::PasskeyDisabled) => {
            error::bad_request("passkey_disabled", "passkey authentication is disabled")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to finish discoverable Passkey authentication");
            error::internal()
        }
    }
}

pub async fn start_passkey_registration(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<PasskeyTicketInput>,
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
    let Some(user_id) = (match state
        .factors
        .user_id_for_ticket(&ticket_id, &holder_hash)
        .await
    {
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
            &ticket_id,
            &holder_hash,
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
            mfa_failure_response(
                &state,
                Some(user_id),
                "passkey_rate_limited",
                source_ip.as_deref(),
                crate::api::user_agent(&headers).as_deref(),
            )
            .await
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
    ApiJson(input): ApiJson<PasskeyRegistrationInput>,
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
        .finish_passkey_registration(
            &ticket_id,
            &holder_hash,
            source_ip.as_deref(),
            &input.credential,
        )
        .await
    {
        Ok(confirmation) => {
            passkey_confirmation_response(&state, confirmation, &headers, source_ip.as_deref())
                .await
        }
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
    ApiJson(input): ApiJson<PasskeyTicketInput>,
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
        .start_passkey_authentication(&ticket_id, &holder_hash, source_ip.as_deref())
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
    ApiJson(input): ApiJson<PasskeyAuthenticationInput>,
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
        .finish_passkey_authentication(
            &ticket_id,
            &holder_hash,
            source_ip.as_deref(),
            &input.credential,
        )
        .await
    {
        Ok(confirmation) => {
            passkey_confirmation_response(&state, confirmation, &headers, source_ip.as_deref())
                .await
        }
        Err(AuthFactorServiceError::PasskeyDisabled) => {
            error::bad_request("passkey_disabled", "passkey authentication is disabled")
        }
        Err(AuthFactorServiceError::RateLimited) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Err(AuthFactorServiceError::PasskeyUpdateConflict) => {
            tracing::warn!(
                event = "auth_factor.passkey.update_conflict",
                "passkey credential compare-and-swap did not apply"
            );
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to finish passkey authentication");
            error::internal()
        }
    }
}
