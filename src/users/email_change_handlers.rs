use crate::{
    api::extract::{ApiJson, SessionWrite},
    audit::AuditEvent,
    error,
    sessions::cookies,
    state::AppState,
};
use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartEmailChangeInput {
    pub new_email: String,
    pub current_password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmEmailChangeInput {
    pub challenge_id: uuid::Uuid,
    pub code: String,
}

#[derive(Debug, Serialize)]
struct EmailChangeStartResponse {
    challenge_id: uuid::Uuid,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: time::OffsetDateTime,
}

pub async fn start_email_change(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
    ApiJson(input): ApiJson<StartEmailChangeInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let scope = format!("chenxing:email-change:start:{}", session.user_id);
    match state.qps.allow_scoped(&scope, 3, 600_000).await {
        Ok(true) => {}
        Ok(false) => {
            return error::too_many_requests(
                "email_change_rate_limited",
                "too many email change attempts; try again later",
            );
        }
        Err(error_value) => {
            tracing::warn!(error = %error_value, "email change rate limiter unavailable");
            return error::internal();
        }
    }
    match state
        .users
        .start_email_change(
            session.user_id,
            &input.new_email,
            &input.current_password,
            source_ip.as_deref(),
            state.clock.now(),
        )
        .await
    {
        Ok(result) => (
            StatusCode::ACCEPTED,
            Json(EmailChangeStartResponse {
                challenge_id: result.challenge_id,
                expires_at: result.expires_at,
            }),
        )
            .into_response(),
        Err(crate::users::service::EmailChangeError::InvalidEmail) => {
            error::bad_request("invalid_email", "email is invalid")
        }
        Err(crate::users::service::EmailChangeError::EmailNotAllowed) => {
            error::bad_request("email_domain_not_allowed", "email domain is not allowed")
        }
        Err(crate::users::service::EmailChangeError::InvalidCredentials) => {
            error::unauthorized("invalid_credentials", "current password is incorrect")
        }
        Err(crate::users::service::EmailChangeError::ReauthenticationUnavailable) => {
            error::forbidden(
                "password_reauthentication_unavailable",
                "password reauthentication is unavailable",
            )
        }
        Err(crate::users::service::EmailChangeError::EncryptionUnavailable) => error::internal(),
        Err(crate::users::service::EmailChangeError::AuthenticationChanged) => {
            error::unauthorized("invalid_session", "login session is invalid")
        }
        Err(crate::users::service::EmailChangeError::Limiter) => error::too_many_requests(
            "email_change_rate_limited",
            "too many email change attempts; try again later",
        ),
        Err(_) => {
            tracing::error!("failed to start email change");
            error::internal()
        }
    }
}

pub async fn confirm_email_change(
    State(state): State<AppState>,
    session: SessionWrite,
    ApiJson(input): ApiJson<ConfirmEmailChangeInput>,
) -> Response {
    match state
        .users
        .confirm_email_change(session.user_id, input.challenge_id, &input.code)
        .await
    {
        Ok(result) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::AuditAction::UserEmailChange,
                    "user_email".to_owned(),
                    Some(session.user_id.to_string()),
                    serde_json::json!({"result": "success"}),
                ))
                .await;
            let mut response = StatusCode::NO_CONTENT.into_response();
            if let Err(error_value) =
                cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure)
            {
                tracing::error!(error = %error_value, "failed to clear cookies after email change");
                return error::internal();
            }
            let sender = state.email_sender.clone();
            let old_email = result.old_email;
            tokio::spawn(async move {
                let _ = sender
                    .send(crate::notifications::EmailMessage {
                        to: old_email,
                        subject: "辰星通行证邮箱已变更".to_owned(),
                        body: "你的账户邮箱已变更。如果这不是你的操作，请立即联系管理员。"
                            .to_owned(),
                    })
                    .await;
            });
            response
        }
        Err(crate::users::service::EmailChangeError::InvalidChallenge) => error::bad_request(
            "email_change_invalid",
            "email change challenge is invalid or expired",
        ),
        Err(crate::users::service::EmailChangeError::EmailConflict) => {
            error::conflict("email_already_registered", "email is already registered")
        }
        Err(crate::users::service::EmailChangeError::AuthenticationChanged) => {
            error::unauthorized("invalid_session", "login session is invalid")
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to confirm email change");
            error::internal()
        }
    }
}
