use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::time::Duration;

use super::{
    domain::{LoginInput, RegistrationError, RegistrationInput},
    service::UserServiceError,
};
use crate::{
    audit::AuditEvent,
    error,
    sessions::{cookies, domain::Session},
    state::AppState,
};

#[derive(Debug, Serialize)]
struct CreatedUserResponse {
    user: super::domain::PublicUser,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    session_id: uuid::Uuid,
    expires_at: time::OffsetDateTime,
}

pub async fn register_user(
    State(state): State<AppState>,
    Json(input): Json<RegistrationInput>,
) -> Response {
    match state.users.register(input).await {
        Ok(user) => {
            state
                .audit
                .record(AuditEvent::new(
                    "system".to_owned(),
                    None,
                    "user_register".to_owned(),
                    "user".to_owned(),
                    Some(user.id.to_string()),
                    serde_json::json!({"result": "success"}),
                ))
                .await;
            (StatusCode::CREATED, Json(CreatedUserResponse { user })).into_response()
        }
        Err(UserServiceError::Validation(RegistrationError::InvalidEmail)) => {
            error::bad_request("invalid_email", "email is invalid")
        }
        Err(UserServiceError::Validation(RegistrationError::PasswordTooShort)) => {
            error::bad_request("password_too_short", "password is too short")
        }
        Err(UserServiceError::Validation(RegistrationError::DisplayNameTooLong)) => {
            error::bad_request("display_name_too_long", "display name is too long")
        }
        Err(UserServiceError::Database(database_error))
            if database_error
                .as_database_error()
                .and_then(|error| error.code())
                .is_some_and(|code| code == "23505") =>
        {
            error::conflict("email_already_registered", "email is already registered")
        }
        Err(UserServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to register user");
            error::internal()
        }
        Err(UserServiceError::PasswordHash) => {
            tracing::error!("failed to hash user password");
            error::internal()
        }
        Err(UserServiceError::InvalidCredentials) => {
            tracing::error!("invalid credentials reached registration handler");
            error::internal()
        }
    }
}

pub async fn login_user(State(state): State<AppState>, Json(input): Json<LoginInput>) -> Response {
    let user_id = match state.users.authenticate(input).await {
        Ok(user_id) => user_id,
        Err(UserServiceError::InvalidCredentials) => {
            return error::unauthorized("invalid_credentials", "email or password is incorrect");
        }
        Err(UserServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to authenticate user");
            return error::internal();
        }
        Err(error) => {
            tracing::error!(error = %error, "unexpected authentication failure");
            return error::internal();
        }
    };

    let ttl = Duration::from_secs(state.config.session_ttl_seconds);
    let session = match Session::new(user_id.to_string(), ttl) {
        Ok(session) => session,
        Err(session_error) => {
            tracing::error!(error = %session_error, "failed to create session");
            return error::internal();
        }
    };
    let response = LoginResponse {
        session_id: session.id,
        expires_at: session.expires_at,
    };
    if let Err(session_error) = state.sessions.save(&session, ttl).await {
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
            serde_json::json!({"result": "success"}),
        ))
        .await;

    let mut response = (StatusCode::OK, Json(response)).into_response();
    cookies::append_login_cookies(
        response.headers_mut(),
        session.id,
        &session.csrf_token,
        state.config.session_ttl_seconds,
        state.config.cookie_secure,
    );
    response
}

pub async fn revoke_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session_id) = cookies::session_id(&headers) else {
        return error::unauthorized("invalid_session", "session is invalid");
    };

    if headers.get("cookie").is_some() {
        let Some(csrf) = cookies::csrf_token(&headers) else {
            return error::bad_request("csrf_required", "CSRF token is required");
        };
        let Some(csrf_cookie) = cookies::csrf_cookie(&headers) else {
            return error::bad_request("csrf_required", "CSRF cookie is required");
        };
        if csrf != csrf_cookie {
            return error::bad_request("csrf_invalid", "CSRF token is invalid");
        }
        let Some(session) = state.sessions.find(session_id).await.ok().flatten() else {
            return error::unauthorized("invalid_session", "session is invalid");
        };
        if !session.validates_csrf(&csrf) {
            return error::bad_request("csrf_invalid", "CSRF token is invalid");
        }
    }

    match state.sessions.revoke(session_id).await {
        Ok(()) => {
            state
                .audit
                .record(AuditEvent::new(
                    "user".to_owned(),
                    None,
                    "session_revoke".to_owned(),
                    "session".to_owned(),
                    Some(session_id.to_string()),
                    serde_json::json!({"result": "success"}),
                ))
                .await;
            let mut response = StatusCode::NO_CONTENT.into_response();
            cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure);
            response
        }
        Err(session_error) => {
            tracing::error!(error = %session_error, "failed to revoke session");
            error::internal()
        }
    }
}
