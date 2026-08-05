use axum::{
    extract::{ConnectInfo, Extension, RawForm, State, rejection::RawFormRejection},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use std::net::SocketAddr;

use super::{
    client_auth::{ClientCredentialError, resolve_client_credentials},
    code::{AUTHORIZATION_CODE_TTL_SECONDS, AuthorizationCode},
    form,
    pkce::verify_s256,
    refresh::RefreshToken,
    refresh_grant::exchange_refresh_token,
    response::{self, issue_token_response},
    session::active_user_id,
    token_security::{enforce_qps, enforce_source_qps, verify_client_credentials},
};
use crate::{error, state::AppState};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    form: Result<RawForm, RawFormRejection>,
) -> Response {
    let RawForm(body) = match form {
        Ok(form) => form,
        Err(_) => {
            return response::with_no_store_headers(error::oauth_bad_request(
                "invalid_request",
                "request body is invalid",
            ));
        }
    };
    let request = match form::deserialize(&body) {
        Some(request) => request,
        None => {
            return response::with_no_store_headers(error::oauth_bad_request(
                "invalid_request",
                "request body is invalid",
            ));
        }
    };
    // #111：通过可信代理列表解析真实客户端 IP，而不是直取 TCP 对端地址。
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    response::with_no_store_headers(
        token_inner(state, headers, source_ip.as_deref(), request).await,
    )
}

async fn token_inner(
    state: AppState,
    headers: HeaderMap,
    source_ip: Option<&str>,
    mut request: TokenRequest,
) -> Response {
    if let Some(source_ip) = source_ip
        && let Some(response) = enforce_source_qps(&state, source_ip).await
    {
        return response;
    }
    let credentials = match resolve_client_credentials(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    ) {
        Ok(credentials) => credentials,
        Err(ClientCredentialError::MultipleMethods | ClientCredentialError::Invalid)
        | Err(ClientCredentialError::Missing) => return error::oauth_invalid_client(),
    };
    request.client_id = Some(credentials.client_id.clone());
    request.client_secret = credentials.client_secret.clone();
    if !matches!(
        request.grant_type.as_str(),
        "authorization_code" | "refresh_token"
    ) {
        return error::oauth_bad_request("unsupported_grant_type", "grant type is unsupported");
    }
    if let Some(response) = verify_client_credentials(&state, &credentials).await {
        return response;
    }
    if let Some(response) = enforce_qps(&state, &credentials.client_id).await {
        return response;
    }
    match request.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(state, request).await,
        "refresh_token" => exchange_refresh_token(state, request).await,
        _ => error::oauth_bad_request("unsupported_grant_type", "grant type is unsupported"),
    }
}

async fn exchange_authorization_code(state: AppState, request: TokenRequest) -> Response {
    let Some(code_value) = request.code.as_deref() else {
        return error::oauth_bad_request("invalid_request", "code is required");
    };
    let Some(redirect_uri) = request.redirect_uri.as_deref() else {
        return error::oauth_bad_request("invalid_request", "redirect_uri is required");
    };
    let Some(code_verifier) = request.code_verifier.as_deref() else {
        return error::oauth_bad_request("invalid_request", "code_verifier is required");
    };
    let code = match state.authorization_codes.find(code_value).await {
        Ok(Some(code)) => code,
        Ok(None) => {
            return error::oauth_bad_request("invalid_grant", "authorization code is invalid");
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve OAuth authorization code");
            return error::oauth_temporarily_unavailable();
        }
    };
    let Some(client_id) = request.client_id.as_deref() else {
        return error::oauth_invalid_client();
    };
    if code.client_id != client_id || code.redirect_uri != redirect_uri {
        return error::oauth_bad_request("invalid_grant", "authorization code is invalid");
    }
    if verify_code_is_redeemable(&code).is_err() {
        return error::oauth_bad_request("invalid_grant", "authorization code is invalid");
    }
    if verify_s256(code_verifier, &code.code_challenge).is_err() {
        tracing::info!("OAuth PKCE verification failed");
        return error::oauth_bad_request("invalid_grant", "authorization code is invalid");
    }
    match active_user_id(&state, &code.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error::oauth_bad_request("invalid_grant", "authorization code is invalid");
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load authorization code user");
            return error::oauth_temporarily_unavailable();
        }
    }
    // 会话绑定校验必须在 take_if_matches 之前：AGENTS.md 要求授权码在绑定、
    // 过期和 PKCE 检查全部通过后才原子消费，否则一次失败请求就烧掉有效凭据。
    let auth_time = match authorization_code_session_auth_time(&state, &code).await {
        Ok(auth_time) => auth_time,
        Err(response) => return response,
    };
    match state
        .authorization_codes
        .take_if_matches(code_value, &code)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return error::oauth_bad_request("invalid_grant", "authorization code is invalid");
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to consume OAuth authorization code");
            return error::oauth_temporarily_unavailable();
        }
    }
    let refresh = RefreshToken::new(
        client_id.to_owned(),
        code.user_id.clone(),
        code.scopes.clone(),
    );
    if let Err(store_error) = state.refresh_tokens.save(&refresh).await {
        tracing::error!(error = %store_error, "failed to store refresh token");
        compensate_authorization_code_exchange(&state, &code, &refresh.value).await;
        return error::oauth_temporarily_unavailable();
    }
    let response = issue_token_response(
        &state,
        &code.user_id,
        client_id,
        &code.scopes,
        Some(refresh.value.clone()),
        code.nonce.as_deref(),
        auth_time,
    )
    .await;
    if response.status() != StatusCode::OK {
        compensate_authorization_code_exchange(&state, &code, &refresh.value).await;
    }
    response
}

/// 校验授权码绑定的会话仍然有效，并返回该会话的认证时刻。
///
/// 返回的时间戳是会话建立时间，用作 ID Token 的 `auth_time`
/// （OIDC Core 1.0 §2：`auth_time` 是终端用户完成认证的时刻，不是令牌签发时刻，
/// 所以不能用 `iat` 顶替）。
///
/// `session_id` 为 `None` 时返回 `Ok(None)`：授权码不是浏览器会话签发的降级路径，
/// 不做会话校验，`auth_time` 也不声明，避免填入错误值。
async fn authorization_code_session_auth_time(
    state: &AppState,
    code: &AuthorizationCode,
) -> Result<Option<i64>, Response> {
    let Some(session_token) = code.session_id.as_deref() else {
        return Ok(None);
    };
    match state.sessions.find(session_token).await {
        Ok(Some(session)) if session.is_active() => Ok(Some(session.created_at.unix_timestamp())),
        Ok(_) => {
            // 会话已撤销或过期（典型场景：用户授权后立刻登出）。
            // 不记录会话令牌，它是凭据。
            tracing::info!(
                client_id = %code.client_id,
                "OAuth authorization code rejected: issuing session is no longer active"
            );
            Err(error::oauth_bad_request(
                "invalid_grant",
                "authorization code is invalid",
            ))
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to load authorization code session");
            Err(error::oauth_temporarily_unavailable())
        }
    }
}

async fn compensate_authorization_code_exchange(
    state: &AppState,
    code: &AuthorizationCode,
    refresh_value: &str,
) {
    if let Err(store_error) = state.refresh_tokens.remove(refresh_value).await {
        tracing::warn!(error = %store_error, "failed to remove refresh token during OAuth compensation");
    }
    let ttl_seconds = authorization_code_restore_ttl(code);
    if let Err(store_error) = state.authorization_codes.restore(code, ttl_seconds).await {
        tracing::warn!(error = %store_error, "failed to restore OAuth authorization code");
    }
}

fn authorization_code_restore_ttl(code: &AuthorizationCode) -> u64 {
    let remaining_seconds = (code.expires_at - time::OffsetDateTime::now_utc()).whole_seconds();
    if remaining_seconds > 0 {
        match u64::try_from(remaining_seconds) {
            Ok(seconds) => seconds,
            Err(_) => AUTHORIZATION_CODE_TTL_SECONDS,
        }
    } else {
        1
    }
}

fn verify_code_is_redeemable(code: &AuthorizationCode) -> Result<(), ()> {
    let mut code = code.clone();
    code.redeem_at(time::OffsetDateTime::now_utc())
        .map_err(|_| ())
}
