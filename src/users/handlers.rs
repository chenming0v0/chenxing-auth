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
    ui_auth::{mutation_error, mutation_user},
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
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<RegistrationInput>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    match state.users.register(input, source_ip.as_deref()).await {
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
        Err(UserServiceError::Validation(RegistrationError::PasswordTooLong)) => {
            error::bad_request(
                "password_too_long",
                "password must be at most 128 characters",
            )
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
        Err(UserServiceError::RateLimited) => error::too_many_requests(
            "registration_rate_limited",
            "too many registration attempts; try again later",
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
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let user_id = match state.users.authenticate(input, source_ip.as_deref()).await {
        Ok(user_id) => user_id,
        Err(UserServiceError::InvalidCredentials) => {
            if record_security_event(
                &state,
                "login_failure",
                None,
                "invalid_credentials",
                Some(&identifier),
                source_ip.as_deref(),
            )
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
            if record_security_event(
                &state,
                "rate_limit_triggered",
                None,
                "login",
                Some(&identifier),
                source_ip.as_deref(),
            )
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
                if record_security_event(
                    &state,
                    "mfa_failure",
                    Some(user_id),
                    "totp_rate_limited",
                    None,
                    source_ip.as_deref(),
                )
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
            if record_security_event(
                &state,
                "mfa_failure",
                Some(user_id),
                "totp_invalid",
                None,
                source_ip.as_deref(),
            )
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
    if setup_required {
        let recovery_required = match state.factors.is_passkey_recovery_required(user_id).await {
            Ok(required) => required,
            Err(factor_error) => {
                tracing::error!(error = %factor_error, "failed to check authentication recovery policy");
                return error::internal();
            }
        };
        if recovery_required
            && record_security_event(
                &state,
                "passkey_recovery_required",
                Some(user_id),
                "passkey_disabled",
                None,
                source_ip.as_deref(),
            )
            .await
            .is_err()
        {
            return error::internal();
        }
    }
    let ticket_methods = if setup_required {
        match state.factors.available_setup_methods().await {
            Ok(methods) => methods,
            Err(factor_error) => {
                tracing::error!(error = %factor_error, "failed to load authentication setup policy");
                return error::internal();
            }
        }
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

/// 撤销当前浏览器会话（自注销）。
///
/// 身份只从 HttpOnly Session Cookie 读取，并复用 `mutation_user` 无条件校验
/// Session Cookie、CSRF Cookie 与 `X-CSRF-Token` 三者绑定。撤销是状态变更，
/// 校验一旦以「请求是否带 Cookie 头」为条件，攻击者只要改走开发期兼容的
/// `x-chenxing-session` 请求头（不发 Cookie 头）就能完整跳过 CSRF 防护。
pub async fn revoke_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Ok(context) = mutation_user(&state, &headers).await else {
        return mutation_error(&state, &headers).await;
    };
    // 撤销目标就是调用者自身的 Cookie 会话，令牌只来自已校验的会话上下文
    let user_id = context.session.user_id;
    let session_id = context.session.id;
    let session_token = context.session.token;

    match state.sessions.revoke(&session_token).await {
        Ok(()) => {
            if state
                .audit
                .record(AuditEvent::new(
                    "user".to_owned(),
                    Some(user_id),
                    "session_revoke".to_owned(),
                    "session".to_owned(),
                    Some(session_id.to_string()),
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
    attempted_identifier: Option<&str>,
    source_ip: Option<&str>,
) -> Result<(), crate::audit::AuditError> {
    state
        .audit
        .record(AuditEvent::authentication_failure(
            action.to_owned(),
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "anonymous".to_owned()
            },
            actor_id.map(|id| id.to_string()),
            "authentication".to_owned(),
            None,
            reason,
            attempted_identifier,
            source_ip,
        ))
        .await
}
