use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::net::SocketAddr;

use super::{
    auth_audit::record_security_event,
    domain::{LoginInput, RegistrationError, RegistrationInput},
    login_use_case::{LoginDecision, LoginUseCaseError, decide_login},
    service::UserServiceError,
};
use crate::{
    api::extract::{ApiJson, SessionWrite},
    audit::AuditEvent,
    auth_factors::{
        handlers::factor_key_unavailable_response,
        session::{
            StaleCredentialCode, factor_required_ticket_response, issue_primary_factor_session,
            issue_verified_session,
        },
    },
    error,
    sessions::cookies,
    state::AppState,
};

#[derive(Debug, Serialize)]
struct CreatedUserResponse {
    user: super::domain::PublicUser,
}

/// 匿名注册状态：`enabled` 是有效值（存储开关 AND Issuer 就绪），
/// `email_verification_required` 是存储值。
#[derive(Debug, Serialize)]
struct RegistrationStatusResponse {
    enabled: bool,
    email_verification_required: bool,
}

/// 公开注册状态查询（匿名，无鉴权）。
///
/// `enabled` 必须反映有效状态而不是裸存储值：Issuer 未配置时
/// `POST /api/v1/users` 被 issuer 闸门关闭，存储开关即使是开的，
/// 对外也必须报关，否则前端会引导用户进入必然失败的注册。
/// 设置不可读时同样报关（fail-closed），不向匿名调用者暴露内部故障细节。
pub async fn registration_status(State(state): State<AppState>) -> Response {
    let (enabled, email_verification_required) = match state.settings.registration().await {
        Ok(setting) => (
            setting.enabled && state.issuer.is_ready(),
            setting.email_verification_required,
        ),
        Err(error_value) => {
            tracing::error!(
                error = %error_value,
                "failed to load registration setting; reporting public registration as closed"
            );
            (false, false)
        }
    };
    (
        StatusCode::OK,
        Json(RegistrationStatusResponse {
            enabled,
            email_verification_required,
        }),
    )
        .into_response()
}

pub async fn register_user(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<RegistrationInput>,
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
        Err(UserServiceError::RegistrationDisabled) => {
            error::forbidden("registration_disabled", "public registration is not open")
        }
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
        Err(
            UserServiceError::CurrentPasswordRequired
            | UserServiceError::PasswordReauthenticationUnavailable,
        ) => {
            tracing::error!("profile-only authentication error reached registration handler");
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
        Err(UserServiceError::ManagementActor(_)) => {
            tracing::error!("management actor validation reached public registration");
            error::internal()
        }
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
    ApiJson(input): ApiJson<LoginInput>,
) -> Response {
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
    // 应用用例返回纯决策；本层只保留审计与 HTTP/Cookie 映射（Issue #140）。
    // `AuthenticatedUser` 绑定本次口令校验所依据的 session_epoch（Issue #274），
    // 后续签发 ticket 或 Session 继续使用该值，不重新读取当前 epoch。
    match decide_login(
        &state.users,
        &state.factors,
        &state.issuer,
        input,
        &identifier,
        source_ip.as_deref(),
    )
    .await
    {
        Err(LoginUseCaseError::User(UserServiceError::InvalidCredentials)) => {
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
            error::unauthorized(
                "invalid_credentials",
                "username, email, or password is incorrect",
            )
        }
        Err(LoginUseCaseError::User(UserServiceError::InvalidLoginInput)) => error::unauthorized(
            "invalid_credentials",
            "username, email, or password is incorrect",
        ),
        Err(LoginUseCaseError::User(UserServiceError::RateLimited)) => {
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
            error::unauthorized(
                "invalid_credentials",
                "username, email, or password is incorrect",
            )
        }
        Err(LoginUseCaseError::User(UserServiceError::Limiter(limiter_error))) => {
            tracing::warn!(
                error = %limiter_error,
                "authentication limiter unavailable during login"
            );
            error::internal()
        }
        Err(LoginUseCaseError::User(UserServiceError::Database(database_error))) => {
            tracing::error!(error = %database_error, "failed to authenticate user");
            error::internal()
        }
        Err(LoginUseCaseError::User(error_value)) => {
            tracing::error!(error = %error_value, "unexpected authentication failure");
            error::internal()
        }
        Err(LoginUseCaseError::Factor(factor_error)) => {
            tracing::error!(error = %factor_error, "failed to load authentication factors");
            error::internal()
        }
        Err(LoginUseCaseError::IssuerRestricted(user_id)) => {
            record_security_event(
                &state,
                crate::audit::AuditAction::LoginFailure,
                Some(user_id),
                "issuer_setup_restricted",
                Some(&identifier),
                source_ip.as_deref(),
                user_agent.as_deref(),
            )
            .await;
            error::unauthorized(
                "invalid_credentials",
                "username, email, or password is incorrect",
            )
        }
        Ok(LoginDecision::TotpAccepted(authenticated)) => {
            issue_verified_session(
                &state,
                authenticated,
                "totp",
                &headers,
                source_ip.as_deref(),
                StaleCredentialCode::InvalidCredentials,
            )
            .await
        }
        // 密钥退役导致的不可验证不是一次凭据失败：单独的审计动作与 503，
        // 且 service 层已归还预留额度，不烧账号/IP 失败计数（#258）。
        Ok(LoginDecision::TotpKeyUnavailable(user_id)) => {
            factor_key_unavailable_response(
                &state,
                Some(user_id),
                source_ip.as_deref(),
                user_agent.as_deref(),
            )
            .await
        }
        Ok(LoginDecision::TotpRejected(user_id)) => {
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
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Ok(LoginDecision::TotpRateLimited(user_id)) => {
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
            error::unauthorized("invalid_factor", "authentication factor is invalid")
        }
        Ok(LoginDecision::PasswordOnly {
            authenticated,
            passkey_recovery_required,
        }) => {
            if passkey_recovery_required {
                record_security_event(
                    &state,
                    crate::audit::AuditAction::PasskeyRecoveryRequired,
                    Some(authenticated.id),
                    "passkey_disabled",
                    None,
                    source_ip.as_deref(),
                    user_agent.as_deref(),
                )
                .await;
            }
            issue_primary_factor_session(
                &state,
                authenticated,
                "password",
                &headers,
                source_ip.as_deref(),
                StaleCredentialCode::InvalidCredentials,
            )
            .await
        }
        Ok(LoginDecision::FactorRequired {
            authenticated,
            methods,
        }) => factor_required_ticket_response(&state, authenticated, methods).await,
    }
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
