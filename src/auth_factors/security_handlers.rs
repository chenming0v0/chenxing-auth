use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{fmt, net::SocketAddr};
use webauthn_rs::prelude::RegisterPublicKeyCredential;
use webauthn_rs_core::proto::CreationChallengeResponse;

use crate::{
    api::extract::{ApiJson, RequestIssuer, SessionRead, SessionWrite},
    audit::AuditEvent,
    auth_factors::service::{
        AuthFactorServiceError, EnrollmentFinish, EnrollmentStart, SelfServiceRemovalOutcome,
    },
    error,
    sessions::cookies,
    state::AppState,
    users::service::UserServiceError,
};

#[derive(Debug, Serialize)]
pub struct FactorSummaryResponse {
    totp_enabled: bool,
    passkey_count: i64,
    available_methods: Vec<crate::auth_factors::domain::FactorMethod>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyInput {}

#[derive(Debug, Serialize)]
pub struct TotpStartResponse<'a> {
    enrollment_id: &'a str,
    secret_base32: &'a str,
    otpauth_url: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpConfirmInput {
    enrollment_id: String,
    code: String,
}

impl fmt::Debug for TotpConfirmInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfirmInput")
            .field("enrollment_id", &self.enrollment_id)
            .field("code", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct PasskeyStartResponse {
    enrollment_id: String,
    options: CreationChallengeResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyFinishInput {
    enrollment_id: String,
    credential: RegisterPublicKeyCredential,
}

impl fmt::Debug for PasskeyFinishInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyFinishInput")
            .field("enrollment_id", &self.enrollment_id)
            .field("credential", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorRemovalInput {
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelEnrollmentInput {
    enrollment_id: String,
    method: crate::auth_factors::domain::FactorMethod,
}

impl fmt::Debug for FactorRemovalInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FactorRemovalInput")
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct EnrollmentResponse {
    method: &'static str,
    enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct RemovalResponse {
    method: &'static str,
    removed: i64,
    credentials_revoked: bool,
}

pub async fn cancel_security_factor_enrollment(
    State(state): State<AppState>,
    session: SessionWrite,
    ApiJson(input): ApiJson<CancelEnrollmentInput>,
) -> Response {
    let session_epoch = match state.users.active_session_epoch(session.user_id).await {
        Ok(Some(epoch)) => epoch,
        Ok(None) => return error::unauthorized("invalid_session", "user session is invalid"),
        Err(user_error) => {
            tracing::error!(error = %user_error, "failed to load session epoch");
            return error::internal();
        }
    };
    match state
        .factors
        .cancel_session_factor_enrollment(
            session.user_id,
            session.session.id,
            session_epoch,
            input.method,
            &input.enrollment_id,
        )
        .await
    {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "cancelled": true })),
        )
            .into_response(),
        Ok(false) => error::not_found(
            "invalid_factor_enrollment",
            "factor enrollment is invalid or expired",
        ),
        Err(factor_error) => factor_internal(factor_error, "cancel authenticated enrollment"),
    }
}

pub async fn current_security_factors(
    State(state): State<AppState>,
    session: SessionRead,
) -> Response {
    match state.factors.session_factor_summary(session.user_id).await {
        Ok(summary) => (
            StatusCode::OK,
            Json(FactorSummaryResponse {
                totp_enabled: summary.totp_enabled,
                passkey_count: summary.passkey_count,
                available_methods: summary.available_methods,
            }),
        )
            .into_response(),
        Err(factor_error) => factor_internal(factor_error, "load current factor summary"),
    }
}

pub async fn start_security_totp_enrollment(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    session: SessionWrite,
    ApiJson(_): ApiJson<EmptyInput>,
) -> Response {
    let Some(profile) = (match state.users.find_profile(session.user_id).await {
        Ok(profile) => profile,
        Err(user_error) => {
            tracing::error!(error = %user_error, "failed to load TOTP enrollment profile");
            return error::internal();
        }
    }) else {
        return error::unauthorized("invalid_session", "user session is invalid");
    };
    match state
        .factors
        .start_session_totp_enrollment(
            session.user_id,
            session.session.id,
            match state.users.active_session_epoch(session.user_id).await {
                Ok(Some(epoch)) => epoch,
                Ok(None) => {
                    return error::unauthorized("invalid_session", "user session is invalid");
                }
                Err(user_error) => {
                    tracing::error!(error = %user_error, "failed to load session epoch");
                    return error::internal();
                }
            },
            &profile.email,
            issuer.issuer().host_str(),
        )
        .await
    {
        Ok(EnrollmentStart::Started(start)) => (
            StatusCode::OK,
            Json(TotpStartResponse {
                enrollment_id: &start.enrollment_id,
                secret_base32: start.enrollment.secret_base32(),
                otpauth_url: start.enrollment.otpauth_url(),
            }),
        )
            .into_response(),
        Ok(EnrollmentStart::AlreadyPending) => error::conflict(
            "factor_enrollment_pending",
            "an enrollment for this factor method is already pending",
        ),
        Ok(EnrollmentStart::AlreadyExists) => {
            error::conflict("totp_already_enabled", "TOTP is already enabled")
        }
        Err(factor_error) => factor_internal(factor_error, "start authenticated TOTP enrollment"),
    }
}

pub async fn confirm_security_totp_enrollment(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
    ApiJson(input): ApiJson<TotpConfirmInput>,
) -> Response {
    let result = state
        .factors
        .confirm_session_totp_enrollment(
            session.user_id,
            session.session.id,
            &input.enrollment_id,
            &input.code,
        )
        .await;
    let source_ip = trusted_source_ip(&state, connect_info, &headers);
    enrollment_finish_response(
        &state,
        result,
        session.user_id,
        "totp",
        &headers,
        source_ip.as_deref(),
    )
    .await
}

pub async fn start_security_passkey_registration(
    State(state): State<AppState>,
    session: SessionWrite,
    ApiJson(_): ApiJson<EmptyInput>,
) -> Response {
    let Some(profile) = (match state.users.find_profile(session.user_id).await {
        Ok(profile) => profile,
        Err(user_error) => {
            tracing::error!(error = %user_error, "failed to load Passkey enrollment profile");
            return error::internal();
        }
    }) else {
        return error::unauthorized("invalid_session", "user session is invalid");
    };
    match state
        .factors
        .start_session_passkey_registration(
            session.user_id,
            session.session.id,
            &profile.email,
            profile.display_name.as_deref().unwrap_or(&profile.username),
        )
        .await
    {
        Ok(EnrollmentStart::Started(start)) => (
            StatusCode::OK,
            Json(PasskeyStartResponse {
                enrollment_id: start.enrollment_id,
                options: start.options,
            }),
        )
            .into_response(),
        Ok(EnrollmentStart::AlreadyPending) => error::conflict(
            "factor_enrollment_pending",
            "an enrollment for this factor method is already pending",
        ),
        Ok(EnrollmentStart::AlreadyExists) => unreachable!("passkey enrollment is additive"),
        Err(AuthFactorServiceError::PasskeyDisabled) => {
            error::bad_request("passkey_disabled", "passkey authentication is disabled")
        }
        Err(factor_error) => {
            factor_internal(factor_error, "start authenticated Passkey registration")
        }
    }
}

pub async fn finish_security_passkey_registration(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
    ApiJson(input): ApiJson<PasskeyFinishInput>,
) -> Response {
    let result = state
        .factors
        .finish_session_passkey_registration(
            session.user_id,
            session.session.id,
            &input.enrollment_id,
            &input.credential,
        )
        .await;
    let source_ip = trusted_source_ip(&state, connect_info, &headers);
    enrollment_finish_response(
        &state,
        result,
        session.user_id,
        "passkey",
        &headers,
        source_ip.as_deref(),
    )
    .await
}

async fn enrollment_finish_response(
    state: &AppState,
    result: Result<EnrollmentFinish, AuthFactorServiceError>,
    user_id: crate::users::domain::UserId,
    method: &'static str,
    headers: &HeaderMap,
    source_ip: Option<&str>,
) -> Response {
    match result {
        Ok(EnrollmentFinish::Completed) => {
            let action = if method == "totp" {
                crate::audit::AuditAction::UserTotpFactorEnroll
            } else {
                crate::audit::AuditAction::UserPasskeyFactorEnroll
            };
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(user_id.to_string()),
                    action,
                    "authentication_factor".to_owned(),
                    Some(user_id.to_string()),
                    crate::audit::with_request_context(
                        serde_json::json!({"result": "success", "method": method}),
                        source_ip,
                        crate::api::user_agent(headers).as_deref(),
                    ),
                ))
                .await;
            (
                StatusCode::OK,
                Json(EnrollmentResponse {
                    method,
                    enabled: true,
                }),
            )
                .into_response()
        }
        Ok(EnrollmentFinish::InvalidEnrollment) => error::bad_request(
            "invalid_factor_enrollment",
            "factor enrollment is invalid or expired",
        ),
        Ok(EnrollmentFinish::InvalidCredential) => {
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Ok(EnrollmentFinish::KeyUnavailable) => error::service_unavailable(
            "factor_key_unavailable",
            "authentication factor enrollment cannot be completed; start again",
        ),
        Ok(EnrollmentFinish::AlreadyExists) => error::conflict(
            "factor_already_enabled",
            "the authentication factor is already enabled",
        ),
        Ok(EnrollmentFinish::AuthenticationChanged) => {
            error::unauthorized("invalid_session", "user session is invalid")
        }
        Err(AuthFactorServiceError::PasskeyDisabled) => {
            error::bad_request("passkey_disabled", "passkey authentication is disabled")
        }
        Err(AuthFactorServiceError::PasskeyConflict) => error::conflict(
            "passkey_credential_conflict",
            "the passkey credential is already registered",
        ),
        Err(factor_error) => factor_internal(factor_error, "finish authenticated enrollment"),
    }
}

pub async fn remove_security_totp_factor(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
    ApiJson(input): ApiJson<FactorRemovalInput>,
) -> Response {
    remove_factor(state, connect_info, headers, session, input, "totp").await
}

pub async fn remove_security_passkey_factor(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
    ApiJson(input): ApiJson<FactorRemovalInput>,
) -> Response {
    remove_factor(state, connect_info, headers, session, input, "passkey").await
}

async fn remove_factor(
    state: AppState,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
    input: FactorRemovalInput,
    method: &'static str,
) -> Response {
    let source_ip = trusted_source_ip(&state, connect_info, &headers);
    let authenticated = match state
        .users
        .reauthenticate_password(session.user_id, &input.password, source_ip.as_deref())
        .await
    {
        Ok(Some(authenticated)) => authenticated,
        Ok(None) => {
            return error::forbidden(
                "password_reauthentication_unavailable",
                "password reauthentication is unavailable; contact an administrator",
            );
        }
        Err(UserServiceError::InvalidCredentials | UserServiceError::RateLimited) => {
            return error::unauthorized(
                "password_reauthentication_failed",
                "password reauthentication failed",
            );
        }
        Err(user_error) => {
            tracing::error!(error = %user_error, "failed to reauthenticate factor removal");
            return error::internal();
        }
    };
    let outcome = if method == "totp" {
        state
            .factors
            .remove_own_totp_factor(session.user_id, authenticated.session_epoch)
            .await
    } else {
        state
            .factors
            .remove_own_passkey_factor(session.user_id, authenticated.session_epoch)
            .await
    };
    let removed = match outcome {
        Ok(SelfServiceRemovalOutcome::Removed { removed }) => removed,
        Ok(SelfServiceRemovalOutcome::Missing) => {
            return error::not_found("factor_not_found", "authentication factor was not found");
        }
        Ok(SelfServiceRemovalOutcome::AuthenticationChanged) => {
            return error::unauthorized(
                "password_reauthentication_failed",
                "password reauthentication failed",
            );
        }
        Err(factor_error) => return factor_internal(factor_error, "remove own factor"),
    };
    let action = if method == "totp" {
        crate::audit::AuditAction::UserTotpFactorRemove
    } else {
        crate::audit::AuditAction::UserPasskeyFactorRemove
    };
    state
        .audit
        .record_best_effort(AuditEvent::new(
            "user".to_owned(),
            Some(session.user_id.to_string()),
            action,
            "authentication_factor".to_owned(),
            Some(session.user_id.to_string()),
            crate::audit::with_request_context(
                serde_json::json!({
                    "result": "success",
                    "method": method,
                    "removed": removed,
                    "credentials_revoked": true,
                    "scope": if method == "passkey" { "all_registered_passkeys" } else { "method" },
                }),
                source_ip.as_deref(),
                crate::api::user_agent(&headers).as_deref(),
            ),
        ))
        .await;
    let mut response = (
        StatusCode::OK,
        Json(RemovalResponse {
            method,
            removed,
            credentials_revoked: true,
        }),
    )
        .into_response();
    if let Err(cookie_error) =
        cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure)
    {
        tracing::error!(error = %cookie_error, "failed to clear revoked factor-removal session cookies");
        return error::internal();
    }
    response
}

fn trusted_source_ip(
    state: &AppState,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: &HeaderMap,
) -> Option<String> {
    crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        headers,
        &state.config.trusted_proxies,
    )
}

fn factor_internal(error_value: AuthFactorServiceError, operation: &str) -> Response {
    tracing::error!(error = %error_value, operation, "authentication factor operation failed");
    error::internal()
}
