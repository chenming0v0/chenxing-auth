use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use super::{
    authorization::{current_admin_mutation, is_bootstrap_token},
    domain::AdminRole,
    session::{ADMIN_CSRF_COOKIE, ADMIN_SESSION_COOKIE},
};
use crate::{audit::AuditEvent, error, sessions::cookies, state::AppState};

pub use super::authorization::admin_csrf_valid;

#[derive(Debug, Deserialize)]
pub struct AdminCredentials {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapAdmin {
    pub email: String,
    pub password: String,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAdmin {
    pub email: String,
    pub password: String,
    pub role: String,
}

pub async fn bootstrap_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BootstrapAdmin>,
) -> Response {
    if !is_bootstrap_token(&state, &headers) {
        return error::unauthorized(
            "admin_required",
            "bootstrap administrator authorization is required",
        );
    }
    let role = match parse_role(input.role.as_deref().unwrap_or("owner")) {
        Some(role) => role,
        None => return error::bad_request("invalid_role", "administrator role is invalid"),
    };
    match state
        .admins
        .bootstrap(&input.email, &input.password, role)
        .await
    {
        Ok(Some(id)) => {
            state
                .audit
                .record(AuditEvent::new(
                    "bootstrap".to_owned(),
                    None,
                    "admin_bootstrap".to_owned(),
                    "admin".to_owned(),
                    Some(id.to_string()),
                    serde_json::json!({"role": role.as_str()}),
                ))
                .await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({"id": id, "role": role.as_str()})),
            )
                .into_response()
        }
        Ok(None) => error::conflict(
            "bootstrap_already_completed",
            "bootstrap administrator is already configured",
        ),
        Err(super::service::AdminServiceError::InvalidEmail) => {
            error::bad_request("invalid_email", "administrator email is invalid")
        }
        Err(super::service::AdminServiceError::PasswordTooShort) => {
            error::bad_request("password_too_short", "administrator password is too short")
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to bootstrap administrator");
            error::internal()
        }
    }
}

pub async fn create_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateAdmin>,
) -> Response {
    if let Err(response) = current_admin_mutation(
        &state,
        &headers,
        super::domain::AdminPermission::ManageUsers,
    )
    .await
    {
        return response;
    }
    let Some(role) = parse_role(&input.role) else {
        return error::bad_request("invalid_role", "administrator role is invalid");
    };
    create_admin_record(&state, &input.email, &input.password, role, "admin").await
}

async fn create_admin_record(
    state: &AppState,
    email: &str,
    password: &str,
    role: AdminRole,
    actor_type: &str,
) -> Response {
    match state.admins.create(email, password, role).await {
        Ok(id) => {
            state
                .audit
                .record(AuditEvent::new(
                    actor_type.to_owned(),
                    None,
                    if actor_type == "bootstrap" {
                        "admin_bootstrap"
                    } else {
                        "admin_create"
                    }
                    .to_owned(),
                    "admin".to_owned(),
                    Some(id.to_string()),
                    serde_json::json!({"role": role.as_str()}),
                ))
                .await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({"id": id, "role": role.as_str()})),
            )
                .into_response()
        }
        Err(super::service::AdminServiceError::Database(database_error))
            if database_error
                .as_database_error()
                .and_then(|error| error.code())
                .is_some_and(|code| code == "23505") =>
        {
            error::conflict(
                "admin_already_registered",
                "administrator email is already registered",
            )
        }
        Err(super::service::AdminServiceError::InvalidEmail) => {
            error::bad_request("invalid_email", "administrator email is invalid")
        }
        Err(super::service::AdminServiceError::PasswordTooShort) => {
            error::bad_request("password_too_short", "administrator password is too short")
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create administrator");
            error::internal()
        }
    }
}

pub async fn login_admin(
    State(state): State<AppState>,
    Json(input): Json<AdminCredentials>,
) -> Response {
    let (admin_id, _) = match state
        .admins
        .authenticate(&input.email, &input.password)
        .await
    {
        Ok(value) => value,
        Err(super::service::AdminServiceError::InvalidCredentials) => {
            return error::unauthorized(
                "invalid_credentials",
                "administrator credentials are invalid",
            );
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate administrator");
            return error::internal();
        }
    };
    let session = match state
        .admin_sessions
        .create(
            admin_id,
            std::time::Duration::from_secs(state.config.session_ttl_seconds),
        )
        .await
    {
        Ok(session) => session,
        Err(redis_error) => {
            tracing::error!(error = %redis_error, "failed to create admin session");
            return error::internal();
        }
    };
    let mut response = (StatusCode::OK, Json(serde_json::json!({"admin_id": admin_id, "expires_in": state.config.session_ttl_seconds}))).into_response();
    cookies::append_named_login_cookies(
        response.headers_mut(),
        ADMIN_SESSION_COOKIE,
        ADMIN_CSRF_COOKIE,
        session.id,
        &session.csrf_token,
        state.config.session_ttl_seconds,
        state.config.cookie_secure,
    );
    response
}

pub async fn logout_admin(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session_id) = super::authorization::admin_session_id(&headers) else {
        return error::unauthorized("invalid_session", "administrator session is invalid");
    };
    let Some(session) = state.admin_sessions.find(session_id).await.ok().flatten() else {
        return error::unauthorized("invalid_session", "administrator session is invalid");
    };
    if !super::authorization::admin_csrf_valid(&headers, &session.csrf_token) {
        return error::bad_request("csrf_invalid", "CSRF token is invalid");
    }
    if let Err(redis_error) = state.admin_sessions.revoke(session_id).await {
        tracing::error!(error = %redis_error, "failed to revoke admin session");
        return error::internal();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    cookies::append_named_clear_cookies(
        response.headers_mut(),
        ADMIN_SESSION_COOKIE,
        ADMIN_CSRF_COOKIE,
        state.config.cookie_secure,
    );
    response
}

fn parse_role(value: &str) -> Option<AdminRole> {
    AdminRole::parse(value)
}
