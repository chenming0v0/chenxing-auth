use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{fmt, net::SocketAddr};

use super::domain::{RegistrationError, UserId};
use super::ui_auth::UserContext;
use crate::{
    api::extract::{SessionRead, SessionWrite},
    error,
    sessions::cookies,
    state::AppState,
};

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
    #[serde(with = "time::serde::rfc3339")]
    current_session_expires_at: time::OffsetDateTime,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileInput {
    pub display_name: Option<String>,
}

#[derive(Deserialize)]
pub struct ChangePasswordInput {
    pub current_password: String,
    pub new_password: String,
}

impl fmt::Debug for ChangePasswordInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangePasswordInput")
            .field("current_password", &"<redacted>")
            .field("new_password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct SessionItem {
    id: i64,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: time::OffsetDateTime,
    current: bool,
}

#[derive(Debug, Serialize)]
struct SessionListResponse {
    items: Vec<SessionItem>,
}

/// 探测登录状态：未登录是正常答案，因此用 `Option<SessionRead>` 而非要求会话。
pub async fn auth_status(session: Option<SessionRead>) -> Response {
    (
        StatusCode::OK,
        Json(AuthStatusResponse {
            authenticated: session.is_some(),
        }),
    )
        .into_response()
}

pub async fn current_user_profile(State(state): State<AppState>, session: SessionRead) -> Response {
    match state.users.find_profile(session.user_id).await {
        Ok(Some(profile)) => profile_response(&session, profile),
        Ok(None) => error::unauthorized("invalid_session", "user session is invalid"),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load current user profile");
            error::internal()
        }
    }
}

pub async fn update_current_user_profile(
    State(state): State<AppState>,
    session: SessionWrite,
    Json(input): Json<UpdateProfileInput>,
) -> Response {
    match state
        .users
        .update_display_name(session.user_id, input.display_name)
        .await
    {
        Ok(Some(profile)) => profile_response(&session, profile),
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
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
    Json(input): Json<ChangePasswordInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    match state
        .users
        .change_password(
            session.user_id,
            &input.current_password,
            &input.new_password,
            source_ip.as_deref(),
        )
        .await
    {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            if let Err(cookie_error) =
                cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure)
            {
                tracing::error!(
                    error = %cookie_error,
                    "failed to build password change cookie response"
                );
                return error::internal();
            }
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
        Err(crate::users::service::UserServiceError::RateLimited) => error::too_many_requests(
            "password_change_rate_limited",
            "too many password change attempts; try again later",
        ),
        Err(crate::users::service::UserServiceError::Limiter(limiter_error)) => {
            tracing::warn!(
                error = %limiter_error,
                "authentication limiter unavailable during password change"
            );
            error::internal()
        }
        Err(crate::users::service::UserServiceError::SourceIpUnavailable) => error::internal(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to change user password");
            error::internal()
        }
    }
}

pub async fn list_user_sessions(State(state): State<AppState>, session: SessionRead) -> Response {
    match state.sessions.list_for_user(session.user_id).await {
        Ok(sessions) => (
            StatusCode::OK,
            Json(SessionListResponse {
                items: sessions
                    .into_iter()
                    .map(|item| SessionItem {
                        current: item.id == session.session.id,
                        id: item.id,
                        created_at: item.created_at,
                        expires_at: item.expires_at,
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
    session: SessionWrite,
    Path(session_id): Path<i64>,
) -> Response {
    match state
        .sessions
        .revoke_for_user(session.user_id, session_id)
        .await
    {
        Ok(true) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            if session_id == session.session.id
                && let Err(cookie_error) = cookies::append_clear_cookies(
                    response.headers_mut(),
                    state.config.cookie_secure,
                )
            {
                tracing::error!(
                    error = %cookie_error,
                    "failed to build session revoke cookie response"
                );
                return error::internal();
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
    context: &UserContext,
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

#[cfg(test)]
mod tests {
    use super::{SessionItem, UserMeResponse};
    use crate::users::domain::UserRole;

    #[test]
    fn user_api_times_serialize_as_rfc3339() {
        let profile = serde_json::to_value(UserMeResponse {
            id: 1,
            username: "owner".to_owned(),
            email: "owner@example.test".to_owned(),
            display_name: None,
            status: "active".to_owned(),
            role: UserRole::Owner,
            current_session_expires_at: time::OffsetDateTime::UNIX_EPOCH,
        })
        .expect("profile serializes");
        let session = serde_json::to_value(SessionItem {
            id: 1,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
            current: true,
        })
        .expect("session serializes");

        assert_eq!(
            profile["current_session_expires_at"],
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(session["created_at"], "1970-01-01T00:00:00Z");
        assert_eq!(session["expires_at"], "1970-01-01T00:00:00Z");
    }
}
