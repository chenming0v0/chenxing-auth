use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::time::Duration;

use crate::{
    audit::AuditEvent,
    error,
    sessions::{cookies, domain::Session},
    state::AppState,
    users::domain::UserId,
};

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub expires_at: time::OffsetDateTime,
}

const SESSION_RESPONSE_MODE_HEADER: &str = "x-chenxing-session-mode";
const SESSION_RESPONSE_TOKEN_MODE: &str = "token";

pub async fn issue_user_session(
    state: &AppState,
    user_id: UserId,
    factor: &str,
    headers: &HeaderMap,
) -> Response {
    let Some(profile) = (match state.users.find_profile(user_id).await {
        Ok(profile) => profile,
        Err(user_error) => {
            tracing::error!(error = %user_error, "failed to load session user");
            return error::internal();
        }
    }) else {
        return error::unauthorized("invalid_session", "user account is invalid");
    };
    if profile.status != "active" {
        return error::unauthorized("user_disabled", "user account is disabled");
    }
    let ttl = Duration::from_secs(state.config.session_ttl_seconds);
    let idle_timeout = Duration::from_secs(state.config.session_idle_timeout_seconds);
    let mut session = match Session::new_with_idle_timeout(user_id.to_string(), ttl, idle_timeout) {
        Ok(session) => session,
        Err(session_error) => {
            tracing::error!(error = %session_error, "failed to create session");
            return error::internal();
        }
    };
    if let Err(session_error) = state.sessions.save(&mut session, ttl).await {
        if matches!(
            &session_error,
            crate::sessions::store::SessionStoreError::UserDisabled
        ) {
            return error::unauthorized("user_disabled", "user account is disabled");
        }
        tracing::error!(error = %session_error, "failed to persist session");
        return error::internal();
    }
    if state
        .audit
        .record(AuditEvent::new(
            "user".to_owned(),
            Some(user_id.to_string()),
            "login".to_owned(),
            "session".to_owned(),
            Some(session.id.to_string()),
            serde_json::json!({"result": "success", "factor": factor}),
        ))
        .await
        .is_err()
    {
        if let Err(error_value) = state.sessions.revoke(&session.token).await {
            tracing::warn!(
                error = %error_value,
                "failed to compensate session after audit persistence failure"
            );
        }
        return error::internal();
    }
    if let Err(factor_error) = state.factors.clear_account_failures(user_id).await {
        if let Err(revoke_error) = state.sessions.revoke(&session.token).await {
            tracing::warn!(
                error = %revoke_error,
                "failed to compensate session after account failure cleanup error"
            );
        }
        tracing::error!(
            error = %factor_error,
            "failed to clear account authentication failures after session issuance"
        );
        return error::internal();
    }
    let mut response = (
        StatusCode::OK,
        Json(LoginResponse {
            session_id: should_return_session_token(
                state.config.session_token_response_enabled,
                headers,
            )
            .then(|| session.token.clone()),
            expires_at: session.expires_at,
        }),
    )
        .into_response();
    cookies::append_login_cookies(
        response.headers_mut(),
        &session.token,
        &session.csrf_token,
        state.config.session_ttl_seconds,
        state.config.cookie_secure,
    );
    cookies::append_clear_login_ticket_cookies(response.headers_mut(), state.config.cookie_secure);
    response
}

fn should_return_session_token(enabled: bool, headers: &HeaderMap) -> bool {
    enabled
        && headers
            .get(SESSION_RESPONSE_MODE_HEADER)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == SESSION_RESPONSE_TOKEN_MODE)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::should_return_session_token;

    #[test]
    fn session_token_response_requires_opt_in_configuration_and_header() {
        let mut headers = HeaderMap::new();
        assert!(!should_return_session_token(false, &headers));
        assert!(!should_return_session_token(true, &headers));

        headers.insert("x-chenxing-session-mode", HeaderValue::from_static("token"));
        assert!(!should_return_session_token(false, &headers));
        assert!(should_return_session_token(true, &headers));
    }
}
