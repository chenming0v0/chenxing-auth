use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::{fmt, net::SocketAddr};

use super::{
    auth_audit::record_security_event,
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
    if !state.issuer.is_ready() {
        return if state.issuer.is_awaiting_configuration() {
            error::issuer_not_configured()
        } else {
            error::issuer_runtime_invalid()
        };
    }
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
                    crate::audit::AuditAction::UserRegister,
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
        Err(UserServiceError::ManageRolesRequired) => error::internal(),
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
    // 审计的 `account_ref` 必须与限流的账号维度用同一个键（Issue #302）。
    // 补丁前这里独立做 `trim().to_ascii_lowercase()`，Unicode 域名下算出的串与
    // `canonical_email` 不同，于是同一个账号按不同书写登录会留下两个不同的
    // `account_ref`，按账号检索审计就漏事件。
    //
    // 解析失败时回落到 trim 后的原样输入：那条路径必然返回 401 且不落审计
    // （`InvalidLoginInput` 分支不记录事件），回落值只用于日志级别的可读性。
    let identifier = match super::domain::parse_login_identifier(input.identifier.trim()) {
        Ok(identifier) => identifier.limiter_key().to_owned(),
        Err(_) => input.identifier.trim().to_owned(),
    };
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    // UA 与源 IP 一起进入认证失败审计（Issue #308），只解析一次。
    let user_agent = crate::api::user_agent(&headers);
    // `authenticated` 绑定了本次口令校验所依据的 session_epoch（Issue #274）。
    // 之后签发 ticket 或 Session 都用它，不再重新读当前 epoch。
    let authenticated = match state.users.authenticate(input, source_ip.as_deref()).await {
        Ok(authenticated) => authenticated,
        Err(UserServiceError::InvalidCredentials) => {
            record_security_event(
                &state,
                crate::audit::AuditAction::LoginFailure,
                None,
                "invalid_credentials",
                Some(&identifier),
                source_ip.as_deref(),
                user_agent.as_deref(),
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
                crate::audit::AuditAction::RateLimitTriggered,
                None,
                "login",
                Some(&identifier),
                source_ip.as_deref(),
                user_agent.as_deref(),
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
    if !state.issuer.local_login_allowed(authenticated.id) {
        record_security_event(
            &state,
            crate::audit::AuditAction::LoginFailure,
            Some(authenticated.id),
            "issuer_setup_restricted",
            Some(&identifier),
            source_ip.as_deref(),
            user_agent.as_deref(),
        )
        .await;
        return error::unauthorized(
            "invalid_credentials",
            "username, email, or password is incorrect",
        );
    }
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
                    crate::audit::AuditAction::MfaFailure,
                    Some(user_id),
                    "totp_rate_limited",
                    None,
                    source_ip.as_deref(),
                    user_agent.as_deref(),
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
                    source_ip.as_deref(),
                    StaleCredentialCode::InvalidCredentials,
                )
                .await;
            }
            // 密钥退役导致的不可验证不是一次凭据失败：单独的审计动作与 503，
            // 且 service 层已归还预留额度，不烧账号/IP 失败计数（#258）。
            FactorVerification::KeyUnavailable => {
                let source_ip = source_ip.as_deref();
                return factor_key_unavailable_response(
                    &state,
                    Some(user_id),
                    source_ip,
                    crate::api::user_agent(&headers).as_deref(),
                )
                .await;
            }
            FactorVerification::Rejected => {
                record_security_event(
                    &state,
                    crate::audit::AuditAction::MfaFailure,
                    Some(user_id),
                    "totp_invalid",
                    None,
                    source_ip.as_deref(),
                    user_agent.as_deref(),
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
                crate::audit::AuditAction::PasskeyRecoveryRequired,
                Some(user_id),
                "passkey_disabled",
                None,
                source_ip.as_deref(),
                user_agent.as_deref(),
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
                crate::audit::AuditAction::LoginFailure,
                Some(user_id),
                "credentials_superseded",
                Some(&identifier),
                source_ip.as_deref(),
                user_agent.as_deref(),
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
pub async fn revoke_session(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
) -> Response {
    // 撤销目标就是调用者自身的 Cookie 会话，令牌只来自已校验的会话上下文
    let user_id = session.session.user_id.clone();
    let session_id = session.session.id;
    let session_token = session.session.token.clone();
    // 请求上下文（源 IP / UA）进入撤销审计，供安全日志详情展示（Issue #308）。
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let user_agent = crate::api::user_agent(&headers);

    match state.sessions.revoke(&session_token).await {
        Ok(()) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(user_id),
                    crate::audit::AuditAction::SessionRevoke,
                    "session".to_owned(),
                    Some(session_id.to_string()),
                    crate::audit::with_request_context(
                        serde_json::json!({"result": "success"}),
                        source_ip.as_deref(),
                        user_agent.as_deref(),
                    ),
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
