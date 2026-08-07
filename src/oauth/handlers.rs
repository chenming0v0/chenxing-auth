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
        AuthorizationRequest, AuthorizationRequestError, MAX_STATE_LENGTH,
        validate_authorization_request_with_allowlist,
    },
    authorization_code_handlers::{
        authorization_quota_redirect, pending_from_validated, restore_pending_after_failure,
    },
    consent::PendingAuthorization,
    session::{SessionLookupError, session_for_headers},
    token_security::enforce_source_qps_with_policy,
};
use crate::{
    error,
    sessions::{cookies, domain::session_token_hash},
    settings::SecurityLimitsSetting,
    state::AppState,
};

pub use super::authorization_code_handlers::{
    AuthorizationCodeIssue, issue_authorization_code_result, validated_pending_request,
};

pub async fn authorize(
    State(state): State<AppState>,
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
        headers,
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        request,
    )
    .await
}

pub async fn authorize_post(
    State(state): State<AppState>,
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
        headers,
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        request,
    )
    .await
}

async fn authorize_request(
    state: AppState,
    headers: HeaderMap,
    peer: Option<SocketAddr>,
    request: AuthorizationRequest,
) -> Response {
    let source_ip = crate::api::source_ip(peer, &headers, &state.config.trusted_proxies);
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
        Err(session_error) => return session_error_response(session_error),
    };
    let Some(session) = session else {
        if !accepts_html(&headers) {
            return error::oauth_unauthorized(
                "login_required",
                "an authenticated session is required",
                "Session realm=\"oauth\"",
            );
        }
        // 还没有会话，pending 以未绑定状态落盘；登录后由绑定接口补上会话。
        let mut pending = pending_from_validated(&validated);
        return save_and_redirect_to_login(&state, &mut pending).await;
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
    // 会话绑定挂到 validated 上：pending 和后续签发的授权码都从这里取值，
    // 已授权直通路径（issue_preconsented_request）才不会丢掉绑定。
    validated.session_token_hash = Some(session_token_hash(&session.token));
    let pending = pending_from_validated(&validated);

    match state
        .consents
        .has_scopes(user_id, &validated.client_id, &validated.scopes)
        .await
    {
        Ok(false) => {
            if let Err(response) = save_pending(&state, &pending).await {
                return response;
            }
            Redirect::to(&format!("/oauth/consent?request_id={}", pending.request_id))
                .into_response()
        }
        Ok(true) => issue_preconsented_request(&state, pending, user_id.to_string()).await,
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load user consent");
            error::oauth_temporarily_unavailable()
        }
    }
}

/// 未登录浏览器命中 `/oauth/authorize`：落盘未绑定的 pending 请求并跳转到 SPA 登录页。
///
/// 同时下发授权请求持有者 Cookie，并把它的 SHA-256 摘要写进 pending 记录（#115）。
/// `request_id` 走 URL 查询参数，可能通过 Referer、浏览器历史或分享链接泄露；
/// 没有这层绑定，任何拿到 `request_id` 的已登录攻击者都能在绑定端点上把这条
/// pending 请求认领到自己的会话并批准，把受害者登录进攻击者账号
/// （OAuth login CSRF / 请求固定）。Cookie 原值只存在于浏览器，服务端只留摘要。
async fn save_and_redirect_to_login(
    state: &AppState,
    pending: &mut PendingAuthorization,
) -> Response {
    let holder = cookies::new_authz_holder();
    pending.holder_hash = Some(cookies::authz_holder_hash(&holder));
    let limits = match load_security_limits(state).await {
        Ok(limits) => limits,
        Err(response) => return response,
    };
    if let Err(response) = save_pending_with_limits(state, pending, &limits).await {
        return response;
    }
    let mut response =
        Redirect::to(&format!("/login?request_id={}", pending.request_id)).into_response();
    // Cookie 生命周期与 pending 记录的 Redis TTL 对齐：pending 过期后 Cookie 也失效。
    if let Err(cookie_error) = cookies::append_authz_holder_cookie(
        response.headers_mut(),
        &holder,
        limits.pending_request_ttl_seconds,
        state.config.cookie_secure,
    ) {
        tracing::error!(error = %cookie_error, "failed to build OAuth holder cookie response");
        return error::internal();
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
    pending: PendingAuthorization,
    user_id: String,
) -> Response {
    if let Err(response) = save_pending(state, &pending).await {
        return response;
    }
    let Some(consumed) = (match state
        .authorization_requests
        .take_if_matches(&pending.request_id, &pending)
        .await
    {
        Ok(consumed) => consumed,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to consume pre-consented OAuth request");
            return error::oauth_temporarily_unavailable();
        }
    }) else {
        return error::oauth_bad_request(
            "invalid_request",
            "authorization request has already been processed",
        );
    };

    let validated = validated_pending_request(consumed.clone());
    match issue_authorization_code_result(state, user_id, validated).await {
        Ok(AuthorizationCodeIssue::Redirect(redirect)) => Redirect::to(&redirect).into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => {
            restore_pending_after_failure(state, &consumed).await;
            authorization_quota_redirect(&consumed)
        }
        Err(response) => {
            restore_pending_after_failure(state, &consumed).await;
            response
        }
    }
}

pub use super::{authorization_code_handlers::issue_authorization_code, token_handlers::token};

fn accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|item| item.trim().starts_with("text/html"))
        })
}

fn authorization_error(
    request: &AuthorizationRequest,
    client: &super::authorization::RegisteredClient,
    validation_error: AuthorizationRequestError,
) -> Response {
    let (code, description) = match validation_error {
        AuthorizationRequestError::InvalidClient => ("invalid_client", "client is invalid"),
        AuthorizationRequestError::RedirectUriNotAllowed => {
            ("invalid_request", "redirect URI is invalid")
        }
        AuthorizationRequestError::UnsupportedResponseType => {
            ("unsupported_response_type", "response type is unsupported")
        }
        AuthorizationRequestError::ScopeNotAllowed => ("invalid_scope", "scope is invalid"),
        AuthorizationRequestError::MissingState => ("invalid_request", "state is required"),
        AuthorizationRequestError::StateTooLong => ("invalid_request", "state is too long"),
        AuthorizationRequestError::NonceTooLong => ("invalid_request", "nonce is too long"),
        AuthorizationRequestError::PkceRequired => ("invalid_request", "PKCE S256 is required"),
        AuthorizationRequestError::InvalidCodeChallenge => {
            ("invalid_request", "code_challenge is invalid")
        }
    };
    if client
        .redirect_uris
        .iter()
        .any(|registered| registered == &request.redirect_uri)
        && let Ok(mut redirect) = url::Url::parse(&request.redirect_uri)
    {
        redirect
            .query_pairs_mut()
            .append_pair("error", code)
            .append_pair("error_description", description);
        if let Some(state) = request
            .state
            .as_deref()
            .filter(|state| !state.is_empty() && state.chars().count() <= MAX_STATE_LENGTH)
        {
            redirect.query_pairs_mut().append_pair("state", state);
        }
        return Redirect::to(redirect.as_str()).into_response();
    }
    error::oauth_bad_request(code, description)
}

fn session_error_response(error_value: SessionLookupError) -> Response {
    tracing::error!(error = %error_value, "OAuth session lookup failed");
    error::oauth_temporarily_unavailable()
}

#[cfg(test)]
#[path = "handlers_tests.rs"]
mod tests;
