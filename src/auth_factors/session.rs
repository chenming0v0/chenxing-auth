use axum::{
    Json,
    http::StatusCode,
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
    pub session_id: String,
    pub expires_at: time::OffsetDateTime,
}

pub async fn issue_user_session(state: &AppState, user_id: UserId, factor: &str) -> Response {
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
    let mut session = match Session::new(user_id.to_string(), ttl) {
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
    state
        .audit
        .record(AuditEvent::new(
            "user".to_owned(),
            Some(user_id.to_string()),
            "login".to_owned(),
            "session".to_owned(),
            Some(session.id.to_string()),
            serde_json::json!({"result": "success", "factor": factor}),
        ))
        .await;
    let mut response = (
        StatusCode::OK,
        Json(LoginResponse {
            session_id: session.token.clone(),
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
    response
}
