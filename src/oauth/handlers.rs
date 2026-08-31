use axum::{
    extract::{
        ConnectInfo, Extension, Form, Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use std::net::SocketAddr;

use super::{
    authorization::{
        AuthorizationRequest, PromptOptions, authentication_is_fresh,
        validate_authorization_request_with_allowlist,
    },
    authorization_code_handlers::{
        authorization_quota_redirect, pending_from_validated, restore_pending_after_failure,
    },
    consent::PendingAuthorization,
    session::session_for_headers,
    token_security::enforce_source_qps_with_policy,
};
#[path = "authorization_errors.rs"]
mod authorization_errors;
use crate::{
    api::extract::RequestIssuer,
    error,
    sessions::{cookies, domain::session_token_hash},
    settings::{IssuerSnapshot, SecurityLimitsSetting},
    state::AppState,
};
use authorization_errors::{
    accepts_html, authorization_dependency_error, authorization_error,
    authorization_error_redirect, session_error_code, trusted_pending_error,
};

pub use super::authorization_code_handlers::{
    AuthorizationCodeIssue, AuthorizationCodeIssueError, issue_authorization_code_result,
    validated_pending_request,
};

pub async fn authorize(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    request: Result<Query<AuthorizationRequest>, QueryRejection>,
) -> Response {
    let Query(request) = match request {
        Ok(request) => request,
        Err(_) => {
            return error::oauth_bad_request("invalid_request", "authorization request is invalid");
        }
    };
    authorize_request(
        state,
        issuer.snapshot(),
        headers,
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        request,
    )
    .await
}

pub async fn authorize_post(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    form: Result<Form<AuthorizationRequest>, FormRejection>,
) -> Response {
    let Form(request) = match form {
        Ok(form) => form,
        Err(_) => {
            return error::oauth_bad_request("invalid_request", "authorization request is invalid");
        }
    };
    authorize_request(
        state,
        issuer.snapshot(),
        headers,
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        request,
    )
    .await
}

async fn authorize_request(
    state: AppState,
    issuer: &IssuerSnapshot,
    headers: HeaderMap,
    peer: Option<SocketAddr>,
    request: AuthorizationRequest,
) -> Response {
    let source_ip = crate::api::source_ip(peer, &headers, &state.config.trusted_proxies);
    // UA 与源 IP 一起进入授权审计（Issue #308），只解析一次。
    let user_agent = crate::api::user_agent(&headers);
    if let Some(response) = enforce_source_qps_with_policy(&state, source_ip.as_deref()).await {
        return response;
    }

    let Some(client) = (match state.clients.find_registered(&request.client_id).await {
        Ok(client) => client,
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load OAuth client");
            return error::oauth_temporarily_unavailable();
        }
    }) else {
        return error::oauth_bad_request("invalid_client", "client is invalid");
    };

    let mut validated = match validate_authorization_request_with_allowlist(
        &client,
        request.clone(),
        &state.config.client_registration_limits.allowed_scopes,
    ) {
        Ok(request) => request,
        Err(validation_error) => {
            tracing::info!(error = %validation_error, "OAuth authorization request rejected");
            return authorization_error(&request, &client, validation_error);
        }
    };

    let session = match session_for_headers(&state, &headers).await {
        Ok(session) => session,
        Err(session_error) => {
            let (code, description) = session_error_code(session_error);
            return authorization_dependency_error(&request, &client, code, description);
        }
    };
    let Some(session) = session else {
        let (prompt_options, _) =
            PromptOptions::parse(validated.prompt.as_deref()).expect("validated prompt must parse");
        if prompt_options.none {
            return authorization_error_redirect(
                &request,
                &client,
                "login_required",
                "an authenticated session is required",
            );
        }
        if !accepts_html(&headers) {
            return error::oauth_unauthorized(
                "login_required",
                "an authenticated session is required",
                "Session realm=\"oauth\"",
            );
        }
        // 还没有会话，pending 以未绑定状态落盘；登录后由绑定接口补上会话。
        validated.reauth_required = prompt_options.requires_login() || validated.max_age.is_some();
        let pending = pending_from_validated(&validated, issuer.generation());
        return save_and_redirect_to_ui(&state, pending, UiDestination::Login, &client).await;
    };

    let user_id = match session.user_id.parse::<crate::users::domain::UserId>() {
        Ok(user_id) => user_id,
        Err(_) => {
            return error::oauth_unauthorized(
                "invalid_session",
                "session user is invalid",
                "Session realm=\"oauth\"",
            );
        }
    };
    let current_session_hash = session_token_hash(&session.token);
    let (prompt_options, _) =
        PromptOptions::parse(validated.prompt.as_deref()).expect("validated prompt must parse");
    let fresh = authentication_is_fresh(session.created_at, state.clock.now(), validated.max_age);
    let reauth_required = prompt_options.requires_login() || !fresh;
    if prompt_options.none && reauth_required {
        return authorization_error_redirect(
            &request,
            &client,
            "login_required",
            "a recent authentication is required",
        );
    }
    // 会话绑定挂到 validated 上：pending 和后续签发的授权码都从这里取值，
    // 已授权直通路径（issue_preconsented_request）才不会丢掉绑定。
    validated.session_token_hash = Some(current_session_hash.clone());
    if reauth_required {
        // Keep the pre-existing session hash as a comparison fence. A later
        // bind from the same session must not satisfy prompt=login/max_age.
        validated.reauth_required = true;
        validated.reauth_session_token_hash = Some(current_session_hash);
        if !accepts_html(&headers) {
            return error::oauth_unauthorized(
                "login_required",
                "a recent authentication is required",
                "Session realm=\"oauth\"",
            );
        }
        let pending = pending_from_validated(&validated, issuer.generation());
        return save_and_redirect_to_ui(&state, pending, UiDestination::Login, &client).await;
    }
    let pending = pending_from_validated(&validated, issuer.generation());

    match state
        .consents
        .has_scopes(user_id, &validated.client_id, &validated.scopes)
        .await
    {
        // 已登录但尚未授权：同样下发 holder Cookie 后进入确认页。会话在确认前
        // 过期或用户切换账号时，绑定端点需要 holder 才能受控重绑（#270）。
        Ok(false) if prompt_options.requires_account_selection() => {
            save_and_redirect_to_ui(&state, pending, UiDestination::Account, &client).await
        }
        Ok(false) if prompt_options.none => authorization_error_redirect(
            &request,
            &client,
            "consent_required",
            "user consent is required",
        ),
        Ok(false) => {
            save_and_redirect_to_ui(&state, pending, UiDestination::Consent, &client).await
        }
        Ok(true) if prompt_options.requires_account_selection() => {
            save_and_redirect_to_ui(&state, pending, UiDestination::Account, &client).await
        }
        Ok(true) if prompt_options.requires_consent() => {
            save_and_redirect_to_ui(&state, pending, UiDestination::Consent, &client).await
        }
        Ok(true) => {
            issue_preconsented_request(
                &state,
                issuer,
                pending,
                user_id.to_string(),
                source_ip.as_deref(),
                user_agent.as_deref(),
                &client,
            )
            .await
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load user consent");
            authorization_dependency_error(
                &request,
                &client,
                "temporarily_unavailable",
                "the authorization server is temporarily unable to handle the request",
            )
        }
    }
}

/// 交给 SPA 处理的交互落点。三者的落盘与 Cookie 处理完全一致，只有 URL 不同。
enum UiDestination {
    /// 未登录：先去登录页，登录后由绑定端点补上会话绑定。
    Login,
    /// 已登录但尚未授权该 scope 组合：直接进授权确认页。
    Consent,
    /// OIDC `prompt=select_account`：让用户显式选择当前账号或切换账号。
    Account,
}

impl UiDestination {
    fn location(&self, request_id: &str) -> String {
        match self {
            Self::Login => format!("/login?request_id={request_id}"),
            Self::Consent => format!("/oauth/consent?request_id={request_id}"),
            Self::Account => format!("/oauth/account?request_id={request_id}"),
        }
    }
}

/// 落盘 pending 请求、下发持有者 Cookie，并把浏览器交给 SPA。
///
/// 持有者 Cookie 的 SHA-256 摘要写进 pending 记录（#115）：`request_id` 走 URL
/// 查询参数，可能通过 Referer、浏览器历史或分享链接泄露；没有这层绑定，任何拿到
/// `request_id` 的已登录攻击者都能在绑定端点上把这条 pending 请求认领到自己的
/// 会话并批准，把受害者登录进攻击者账号（OAuth login CSRF / 请求固定）。
/// Cookie 原值只存在于浏览器，服务端只留摘要。
///
/// 三条进入 SPA 的路径都必须下发它（#270）：holder 是绑定端点唯一的所有权凭据，
/// 已登录路径若不下发，用户在确认前会话过期或切换账号后就再也无法重绑，
/// 只能在登录页与确认页之间打转。
async fn save_and_redirect_to_ui(
    state: &AppState,
    mut pending: PendingAuthorization,
    destination: UiDestination,
    client: &super::authorization::RegisteredClient,
) -> Response {
    let holder = cookies::new_authz_holder();
    pending.holder_hash = Some(cookies::authz_holder_hash(&holder));
    let limits = match load_security_limits(state).await {
        Ok(limits) => limits,
        Err(_) => {
            return trusted_pending_error(
                &pending,
                client,
                "temporarily_unavailable",
                "the authorization server is temporarily unable to handle the request",
            );
        }
    };
    if let Err(_response) = save_pending_with_limits(state, &pending, &limits).await {
        return trusted_pending_error(
            &pending,
            client,
            "temporarily_unavailable",
            "the authorization server is temporarily unable to handle the request",
        );
    }
    let mut response = Redirect::to(&destination.location(&pending.request_id)).into_response();
    // Cookie 生命周期与 pending 记录的 Redis TTL 对齐：pending 过期后 Cookie 也失效。
    if let Err(cookie_error) = cookies::append_authz_holder_cookie(
        response.headers_mut(),
        &holder,
        limits.pending_request_ttl_seconds,
        state.config.cookie_secure,
    ) {
        tracing::error!(error = %cookie_error, "failed to build OAuth holder cookie response");
        return trusted_pending_error(
            &pending,
            client,
            "server_error",
            "the authorization server encountered an unexpected condition",
        );
    }
    response
}

async fn save_pending(state: &AppState, pending: &PendingAuthorization) -> Result<(), Response> {
    let limits = load_security_limits(state).await?;
    save_pending_with_limits(state, pending, &limits).await
}

async fn save_pending_with_limits(
    state: &AppState,
    pending: &PendingAuthorization,
    limits: &SecurityLimitsSetting,
) -> Result<(), Response> {
    match state
        .authorization_requests
        .save_limited_with_limits(pending, limits)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(error::oauth_too_many_requests(
            "temporarily_unavailable",
            "too many pending authorization requests",
        )),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to store OAuth authorization request");
            Err(error::oauth_temporarily_unavailable())
        }
    }
}

async fn load_security_limits(state: &AppState) -> Result<SecurityLimitsSetting, Response> {
    state
        .settings
        .security_limits()
        .await
        .map_err(|error_value| {
            tracing::error!(error = %error_value, "failed to load OAuth security limits");
            error::oauth_temporarily_unavailable()
        })
}

async fn issue_preconsented_request(
    state: &AppState,
    issuer: &IssuerSnapshot,
    pending: PendingAuthorization,
    user_id: String,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
    client: &super::authorization::RegisteredClient,
) -> Response {
    if let Err(response) = save_pending(state, &pending).await {
        let _ = response;
        return trusted_pending_error(
            &pending,
            client,
            "temporarily_unavailable",
            "the authorization server is temporarily unable to handle the request",
        );
    }
    let Some(consumed) = (match state
        .authorization_requests
        .take_if_matches_with_ttl(&pending.request_id, &pending)
        .await
    {
        Ok(consumed) => consumed,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to consume pre-consented OAuth request");
            return trusted_pending_error(
                &pending,
                client,
                "temporarily_unavailable",
                "the authorization server is temporarily unable to handle the request",
            );
        }
    }) else {
        return trusted_pending_error(
            &pending,
            client,
            "invalid_request",
            "authorization request has already been processed",
        );
    };

    let validated = validated_pending_request(consumed.request.clone());
    match issue_authorization_code_result(state, issuer, user_id, validated, source_ip, user_agent)
        .await
    {
        Ok(AuthorizationCodeIssue::Redirect(redirect)) => Redirect::to(&redirect).into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => {
            restore_pending_after_failure(state, &consumed.request, consumed.remaining_ttl_ms)
                .await;
            authorization_quota_redirect(&consumed.request)
        }
        Err(
            AuthorizationCodeIssueError::LoginRequired
            | AuthorizationCodeIssueError::InvalidSession,
        ) => trusted_pending_error(
            &consumed.request,
            client,
            "login_required",
            "a recent authentication is required",
        ),
        Err(response) => {
            restore_pending_after_failure(state, &consumed.request, consumed.remaining_ttl_ms)
                .await;
            let _ = response;
            trusted_pending_error(
                &consumed.request,
                client,
                "temporarily_unavailable",
                "the authorization server is temporarily unable to handle the request",
            )
        }
    }
}

pub use super::{authorization_code_handlers::issue_authorization_code, token_handlers::token};

#[cfg(test)]
#[path = "handlers_tests.rs"]
mod tests;
