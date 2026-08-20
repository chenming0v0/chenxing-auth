use axum::{extract::{ConnectInfo, Extension, State}, http::HeaderMap, response::{IntoResponse, Response}, Json};
use std::net::SocketAddr;

use crate::{api::extract::SessionWrite, audit::AuditEvent, auth_factors::service::{AuthFactorServiceError, SelfServiceRemovalOutcome}, error, sessions::cookies, state::AppState, users::service::UserServiceError};

use super::{factor_internal, FactorRemovalInput, RemovalResponse, trusted_source_ip};

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
