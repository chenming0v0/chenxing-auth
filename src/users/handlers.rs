use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::{fmt, net::SocketAddr};

use super::{
    domain::{LoginInput, RegistrationError, RegistrationInput},
    service::UserServiceError,
};
use crate::{
    api::extract::SessionWrite,
    audit::AuditEvent,
    auth_factors::{
        handlers::factor_key_unavailable_response,
        service::FactorVerification,
        session::{StaleCredentialCode, issue_user_session},
    },
    error,
    sessions::cookies,
    state::AppState,
};

#[derive(Debug, Serialize)]
struct CreatedUserResponse {
    user: super::domain::PublicUser,
}

#[derive(Serialize)]
struct PendingLoginResponse {
    status: &'static str,
    methods: Vec<crate::auth_factors::domain::FactorMethod>,
}

impl fmt::Debug for PendingLoginResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingLoginResponse")
            .field("status", &self.status)
            .field("login_ticket", &"<redacted>")
            .field("methods", &self.methods)
            .finish()
    }
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
            state
                .audit
                .record_best_effort(AuditEvent::new(
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
        Err(UserServiceError::EmailVerificationUnavailable) => error::service_unavailable(
            "email_verification_unavailable",
            "email ownership verification is temporarily unavailable",
        ),
        Err(UserServiceError::Database(database_error))
            if database_error
                .as_database_error()
                .and_then(|error| error.code())
                .is_some_and(|code| code == "23505") =>
        {
            error::conflict(
                "registration_conflict",
                "registration details are unavailable",
            )
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
        // 公开注册没有同事务审计要求，这个变体到不了这里；保留分支只为让新增
        // `UserServiceError` 变体在编译期被发现，而不是落进兜底的 500。
        Err(UserServiceError::AuditUnavailable) => error::internal(),
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
    // `authenticated` 绑定了本次口令校验所依据的 session_epoch（Issue #274）。
    // 之后签发 ticket 或 Session 都用它，不再重新读当前 epoch。
    let authenticated = match state.users.authenticate(input, source_ip.as_deref()).await {
        Ok(authenticated) => authenticated,
        Err(UserServiceError::InvalidCredentials) => {
            record_security_event(
                &state,
                "login_failure",
                None,
                "invalid_credentials",
                Some(&identifier),
                source_ip.as_deref(),
            )
            .await;
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
            record_security_event(
                &state,
                "rate_limit_triggered",
                None,
                "login",
                Some(&identifier),
                source_ip.as_deref(),
            )
            .await;
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
    let user_id = authenticated.id;

    let methods = match state.factors.available_methods(user_id).await {
        Ok(methods) => methods,
        Err(factor_error) => {
            tracing::error!(error = %factor_error, "failed to load authentication factors");
            return error::internal();
        }
    };
    if methods.contains(&crate::auth_factors::domain::FactorMethod::Totp) && totp_code.is_some() {
        let verification = match state
            .factors
            .verify_totp(
                user_id,
                &identifier,
                source_ip.as_deref(),
                totp_code.as_deref().unwrap_or_default(),
            )
            .await
        {
            Ok(verification) => verification,
            Err(crate::auth_factors::service::AuthFactorServiceError::RateLimited) => {
                record_security_event(
                    &state,
                    "mfa_failure",
                    Some(user_id),
                    "totp_rate_limited",
                    None,
                    source_ip.as_deref(),
                )
                .await;
                return error::unauthorized("invalid_factor", "authentication factor is invalid");
            }
            Err(factor_error) => {
                tracing::error!(error = %factor_error, "failed to verify TOTP");
                return error::internal();
            }
        };
        match verification {
            FactorVerification::Accepted => {
                return issue_user_session(
                    &state,
                    authenticated,
                    "totp",
                    &headers,
                    StaleCredentialCode::InvalidCredentials,
                )
                .await;
            }
            // 密钥退役导致的不可验证不是一次凭据失败：单独的审计动作与 503，
            // 且 service 层已归还预留额度，不烧账号/IP 失败计数（#258）。
            FactorVerification::KeyUnavailable => {
                let source_ip = source_ip.as_deref();
                return factor_key_unavailable_response(&state, Some(user_id), source_ip).await;
            }
            FactorVerification::Rejected => {
                record_security_event(
                    &state,
                    "mfa_failure",
                    Some(user_id),
                    "totp_invalid",
                    None,
                    source_ip.as_deref(),
                )
                .await;
                return error::unauthorized("invalid_factor", "authentication factor is invalid");
            }
        }
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
        if recovery_required {
            record_security_event(
                &state,
                "passkey_recovery_required",
                Some(user_id),
                "passkey_disabled",
                None,
                source_ip.as_deref(),
            )
            .await;
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
    let holder = cookies::new_login_ticket_holder();
    let holder_hash = cookies::login_ticket_holder_hash(&holder);
    let (login_ticket, _) = match state
        .factors
        .create_login_ticket(authenticated, ticket_methods.clone(), &holder_hash)
        .await
    {
        Ok(ticket) => ticket,
        // 并发改密作废了本次口令：与其他凭据失败共用 401 invalid_credentials，
        // 不签发任何 ticket，也不向调用方暴露"刚刚发生过改密"。
        Err(crate::auth_factors::service::AuthFactorServiceError::AuthenticationEpochChanged) => {
            record_security_event(
                &state,
                "login_failure",
                Some(user_id),
                "credentials_superseded",
                Some(&identifier),
                source_ip.as_deref(),
            )
            .await;
            return error::unauthorized(
                "invalid_credentials",
                "username, email, or password is incorrect",
            );
        }
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
    let mut response = (
        StatusCode::ACCEPTED,
        Json(PendingLoginResponse {
            status,
            methods: ticket_methods,
        }),
    )
        .into_response();
    if let Err(cookie_error) = cookies::append_login_ticket_cookies(
        response.headers_mut(),
        &login_ticket,
        &holder,
        crate::auth_factors::domain::LoginTicket::TTL.whole_seconds() as u64,
        state.config.cookie_secure,
    ) {
        tracing::error!(error = %cookie_error, "failed to build login ticket cookie response");
        return error::internal();
    }
    response
}

/// 撤销当前浏览器会话（自注销）。
///
/// 身份只从 HttpOnly Session Cookie 读取。`SessionWrite` 在提取阶段无条件校验
/// Session Cookie、CSRF Cookie 与 `X-CSRF-Token` 三者绑定。撤销是状态变更，
/// 校验一旦以「请求是否带 Cookie 头」为条件，攻击者只要改走开发期兼容的
/// `x-chenxing-session` 请求头（不发 Cookie 头）就能完整跳过 CSRF 防护。
pub async fn revoke_session(State(state): State<AppState>, session: SessionWrite) -> Response {
    // 撤销目标就是调用者自身的 Cookie 会话，令牌只来自已校验的会话上下文
    let user_id = session.session.user_id.clone();
    let session_id = session.session.id;
    let session_token = session.session.token.clone();

    match state.sessions.revoke(&session_token).await {
        Ok(()) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(user_id),
                    "session_revoke".to_owned(),
                    "session".to_owned(),
                    Some(session_id.to_string()),
                    serde_json::json!({"result": "success"}),
                ))
                .await;
            let mut response = StatusCode::NO_CONTENT.into_response();
            if let Err(cookie_error) =
                cookies::append_clear_cookies(response.headers_mut(), state.config.cookie_secure)
            {
                tracing::error!(error = %cookie_error, "failed to build logout cookie response");
                return error::internal();
            }
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
) {
    state
        .audit
        .record_best_effort(AuditEvent::authentication_failure(
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
        .await;
}
