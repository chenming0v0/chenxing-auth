use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::domain::{RegistrationError, UserId};
use super::ui_auth::{UserContext, current_user, mutation_error, mutation_user};
use crate::{error, sessions::cookies, state::AppState};

#[derive(Debug, Serialize)]
struct AuthStatusResponse {
    authenticated: bool,
}

#[derive(Debug, Serialize)]
struct UserMeResponse {
    id: UserId,
    username: String,
    email: String,
    display_name: Option<String>,
    status: String,
    role: super::domain::UserRole,
    current_session_expires_at: time::OffsetDateTime,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileInput {
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordInput {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
struct SessionItem {
    id: i64,
    created_at: time::OffsetDateTime,
    expires_at: time::OffsetDateTime,
    current: bool,
}

#[derive(Debug, Serialize)]
struct SessionListResponse {
    items: Vec<SessionItem>,
}

pub async fn auth_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let authenticated = current_user(&state, &headers).await.is_ok();
    (StatusCode::OK, Json(AuthStatusResponse { authenticated })).into_response()
}

pub async fn current_user_profile(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match current_user(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match state.users.find_profile(context.user_id).await {
        Ok(Some(profile)) => profile_response(context, profile),
        Ok(None) => error::unauthorized("invalid_session", "user session is invalid"),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load current user profile");
            error::internal()
        }
    }
}

pub async fn update_current_user_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UpdateProfileInput>,
) -> Response {
    let Ok(context) = mutation_user(&state, &headers).await else {
        return mutation_error(&state, &headers).await;
    };
    match state
        .users
        .update_display_name(context.user_id, input.display_name)
        .await
    {
        Ok(Some(profile)) => profile_response(context, profile),
        Ok(None) => error::unauthorized("invalid_session", "user session is invalid"),
        Err(crate::users::service::UserServiceError::Validation(validation_error)) => {
            error::bad_request("invalid_display_name", validation_error.to_string())
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update user profile");
            error::internal()
        }
    }
}

pub async fn change_current_user_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ChangePasswordInput>,
) -> Response {
    let Ok(context) = mutation_user(&state, &headers).await else {
        return mutation_error(&state, &headers).await;
    };
    match state
        .users
        .change_password(
            context.user_id,
            &input.current_password,
            &input.new_password,
        )
        .await
    {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure);
            response
        }
        Err(crate::users::service::UserServiceError::InvalidCredentials) => {
            error::unauthorized("invalid_credentials", "current password is incorrect")
        }
        Err(crate::users::service::UserServiceError::Validation(
            RegistrationError::PasswordTooShort,
        )) => error::bad_request("password_too_short", "password is too short"),
        Err(crate::users::service::UserServiceError::Validation(
            RegistrationError::PasswordTooLong,
        )) => error::bad_request(
            "password_too_long",
            "password must be at most 128 characters",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to change user password");
            error::internal()
        }
    }
}

pub async fn list_user_sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let context = match current_user(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match state.sessions.list_for_user(context.user_id).await {
        Ok(sessions) => (
            StatusCode::OK,
            Json(SessionListResponse {
                items: sessions
                    .into_iter()
                    .map(|session| SessionItem {
                        current: session.id == context.session.id,
                        id: session.id,
                        created_at: session.created_at,
                        expires_at: session.expires_at,
                    })
                    .collect(),
            }),
        )
            .into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list user sessions");
            error::internal()
        }
    }
}

pub async fn revoke_user_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<i64>,
) -> Response {
    let Ok(context) = mutation_user(&state, &headers).await else {
        return mutation_error(&state, &headers).await;
    };
    match state
        .sessions
        .revoke_for_user(context.user_id, session_id)
        .await
    {
        Ok(true) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            if session_id == context.session.id {
                cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure);
            }
            response
        }
        Ok(false) => error::not_found("session_not_found", "session was not found"),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to revoke user session");
            error::internal()
        }
    }
}

fn profile_response(
    context: UserContext,
    profile: crate::users::repository::UserProfile,
) -> Response {
    (
        StatusCode::OK,
        Json(UserMeResponse {
            id: profile.id,
            username: profile.username,
            email: profile.email,
            display_name: profile.display_name,
            status: profile.status,
            role: profile.role,
            current_session_expires_at: context.session.expires_at,
        }),
    )
        .into_response()
}
