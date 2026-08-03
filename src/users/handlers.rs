use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::net::SocketAddr;

use super::{
    domain::{LoginInput, RegistrationError, RegistrationInput},
    service::UserServiceError,
};
use crate::{
    audit::AuditEvent, auth_factors::session::issue_user_session, error, sessions::cookies,
    state::AppState,
};

#[derive(Debug, Serialize)]
struct CreatedUserResponse {
    user: super::domain::PublicUser,
}

#[derive(Debug, Serialize)]
struct PendingLoginResponse {
    status: &'static str,
    login_ticket: String,
    methods: Vec<crate::auth_factors::domain::FactorMethod>,
}

pub async fn register_user(
    State(state): State<AppState>,
    Json(input): Json<RegistrationInput>,
) -> Response {
    match state.users.register(input).await {
        Ok(user) => {
            if state
                .audit
                .record(AuditEvent::new(
                    "system".to_owned(),
                    None,
                    "user_register".to_owned(),
                    "user".to_owned(),
                    Some(user.id.to_string()),
                    serde_json::json!({"result": "success"}),
                ))
                .await
                .is_err()
            {
                return error::internal();
            }
            (StatusCode::CREATED, Json(CreatedUserResponse { user })).into_response()
        }
        Err(UserServiceError::Validation(RegistrationError::InvalidEmail)) => {
            error::bad_request("invalid_email", "email is invalid")
        }
        Err(UserServiceError::EmailDomainNotAllowed) => {
            error::bad_request("email_domain_not_allowed", "email domain is not allowed")
        }
        Err(UserServiceError::Validation(RegistrationError::InvalidUsername)) => {
            error::bad_request("invalid_username", "username is invalid")
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
            let constraint = database_error
                .as_database_error()
                .and_then(|error| error.constraint())
                .unwrap_or_default();
            if constraint == "users_username_key" {
                error::conflict(
                    "username_already_registered",
                    "username is already registered",
                )
            } else {
                error::conflict("email_already_registered", "email is already registered")
            }
        }
        Err(UserServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to register user");
            error::internal()
        }
        Err(UserServiceError::PasswordHash) => {
            tracing::error!("failed to hash user password");
            error::internal()
        }
        Err(UserServiceError::InvalidLoginInput) => {
            tracing::error!("login input validation reached registration handler");
            error::internal()
        }
        Err(UserServiceError::InvalidCredentials) => {
            tracing::error!("invalid credentials reached registration handler");
            error::internal()
        }
        Err(UserServiceError::RateLimited) => error::unauthorized(
            "invalid_credentials",
            "username, email, or password is incorrect",
        ),
        Err(UserServiceError::Limiter(limiter_error)) => {
            tracing::warn!(
                error = %limiter_error,
                "authentication limiter unavailable during registration"
            );
            error::internal()
        }
        Err(UserServiceError::SourceIpUnavailable) => error::internal(),
        Err(UserServiceError::LastOwnerRequired) => error::internal(),
        Err(UserServiceError::OwnerBootstrapRequired) => error::conflict(
            "owner_bootstrap_required",
            "owner bootstrap must be completed before public registration",
        ),
    }
}

pub async fn login_user(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<LoginInput>,
) -> Response {
    let totp_code = input.totp_code.clone();
    let identifier = input.identifier.trim().to_ascii_lowercase();
    let source_ip = crate::api::source_ip(connect_info.map(|Extension(ConnectInfo(peer))| peer));
    let user_id = match state.users.authenticate(input, source_ip.as_deref()).await {
        Ok(user_id) => user_id,
        Err(UserServiceError::InvalidCredentials) => {
            if record_security_event(&state, "login_failure", None, "invalid_credentials")
                .await
                .is_err()
            {
                return error::internal();
            }
            return error::unauthorized(
                "invalid_credentials",
                "username, email, or password is incorrect",
            );
        }
        Err(UserServiceError::InvalidLoginInput) => {
            return error::unauthorized(
                "invalid_credentials",
                "username, email, or password is incorrect",
            );
        }
        Err(UserServiceError::RateLimited) => {
            if record_security_event(&state, "rate_limit_triggered", None, "login")
                .await
                .is_err()
            {
                return error::internal();
            }
            return error::unauthorized(
                "invalid_credentials",
                "username, email, or password is incorrect",
            );
        }
        Err(UserServiceError::Limiter(limiter_error)) => {
            tracing::warn!(
                error = %limiter_error,
                "authentication limiter unavailable during login"
            );
            return error::internal();
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

    let methods = match state.factors.available_methods(user_id).await {
        Ok(methods) => methods,
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to load authentication factors");
            return error::internal();
        }
    };
    if methods.contains(&crate::auth_factors::domain::FactorMethod::Totp) && totp_code.is_some() {
        let valid = match state
            .factors
            .verify_totp(
                user_id,
                &identifier,
                source_ip.as_deref(),
                totp_code.as_deref().unwrap_or_default(),
            )
            .await
        {
            Ok(valid) => valid,
            Err(crate::auth_factors::service::AuthFactorServiceError::RateLimited) => {
                if record_security_event(&state, "mfa_failure", Some(user_id), "totp_rate_limited")
                    .await
                    .is_err()
                {
                    return error::internal();
                }
                return error::unauthorized("invalid_factor", "authentication factor is invalid");
            }
            Err(factor_error) => {
                tracing::error!(error = %factor_error, "failed to verify TOTP");
                return error::internal();
            }
        };
        if !valid {
            if record_security_event(&state, "mfa_failure", Some(user_id), "totp_invalid")
                .await
                .is_err()
            {
                return error::internal();
            }
            return error::unauthorized("invalid_factor", "authentication factor is invalid");
        }
        return issue_user_session(&state, user_id, "totp", &headers).await;
    }

    let setup_required = methods.is_empty();
    let ticket_methods = if setup_required {
        vec![
            crate::auth_factors::domain::FactorMethod::Totp,
            crate::auth_factors::domain::FactorMethod::Passkey,
        ]
    } else {
        methods
    };
    let (login_ticket, _) = match state
        .factors
        .create_login_ticket(user_id, ticket_methods.clone())
        .await
    {
        Ok(ticket) => ticket,
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to create pending login ticket");
            return error::internal();
        }
    };
    let status = if setup_required {
        "factor_setup_required"
    } else {
        "factor_required"
    };
    (
        StatusCode::ACCEPTED,
        Json(PendingLoginResponse {
            status,
            login_ticket,
            methods: ticket_methods,
        }),
    )
        .into_response()
}

pub async fn revoke_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session_token) = cookies::session_id(&headers) else {
        return error::unauthorized("invalid_session", "session is invalid");
    };
    let session = match state.sessions.find(&session_token).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            let mut response = error::unauthorized("invalid_session", "session is invalid");
            cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure);
            return response;
        }
        Err(session_error) => {
            tracing::error!(error = %session_error, "failed to load session for revocation");
            return error::internal();
        }
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
        if !session.validates_csrf(&csrf) {
            return error::bad_request("csrf_invalid", "CSRF token is invalid");
        }
    }

    match state.sessions.revoke(&session_token).await {
        Ok(()) => {
            if state
                .audit
                .record(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id),
                    "session_revoke".to_owned(),
                    "session".to_owned(),
                    Some(session.id.to_string()),
                    serde_json::json!({"result": "success"}),
                ))
                .await
                .is_err()
            {
                return error::internal();
            }
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

async fn record_security_event(
    state: &AppState,
    action: &str,
    actor_id: Option<crate::users::domain::UserId>,
    reason: &str,
) -> Result<(), crate::audit::AuditError> {
    state
        .audit
        .record(AuditEvent::new(
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "anonymous".to_owned()
            },
            actor_id.map(|id| id.to_string()),
            action.to_owned(),
            "authentication".to_owned(),
            None,
            serde_json::json!({"reason": reason}),
        ))
        .await
}


