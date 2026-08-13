use axum::{
    Json,
    extract::{ConnectInfo, Extension, RawForm, State, rejection::RawFormRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

pub use super::token_use_case::TokenRequest;
use super::{
    client_auth::resolve_client_credentials,
    form,
    refresh_grant::exchange_refresh_token,
    response,
    token_security::{enforce_qps, enforce_source_qps_with_policy, verify_client_credentials},
    token_use_case::{self, OAuthError},
};
use crate::{error, state::AppState};

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
    if let Some(response) = enforce_source_qps_with_policy(&state, source_ip).await {
        return response;
    }
    let credentials = match resolve_client_credentials(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    ) {
        Ok(credentials) => credentials,
        // 缺失、格式错误、超长或方式混用都是客户端认证失败，按 RFC 6749
        // 统一返回 invalid_client（Issue #353：超长凭据必须在解析层被拒）。
        Err(_) => return error::oauth_invalid_client(),
    };
    request.client_id = Some(credentials.client_id.clone());
    request.client_secret = credentials.client_secret.clone();
    if !matches!(
        request.grant_type.as_str(),
        "authorization_code" | "refresh_token"
    ) {
        return error::oauth_bad_request("unsupported_grant_type", "grant type is unsupported");
    }
    let authenticated = match verify_client_credentials(&state, &credentials).await {
        Ok(authenticated) => authenticated,
        Err(response) => return response,
    };
    if let Some(response) = enforce_qps(&state, &credentials.client_id).await {
        return response;
    }
    match request.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(state, request, authenticated).await,
        "refresh_token" => exchange_refresh_token(state, request, authenticated).await,
        _ => error::oauth_bad_request("unsupported_grant_type", "grant type is unsupported"),
    }
}

async fn exchange_authorization_code(
    state: AppState,
    request: TokenRequest,
    authenticated: crate::clients::service::AuthenticatedClient,
) -> Response {
    match token_use_case::exchange_code(&state, request, authenticated).await {
        Ok(token) => Json(token).into_response(),
        Err(error) => oauth_error_response(error),
    }
}

fn oauth_error_response(error_value: OAuthError) -> Response {
    match error_value {
        OAuthError::BadRequest { code, description } => error::oauth_bad_request(code, description),
        OAuthError::InvalidClient => error::oauth_invalid_client(),
        OAuthError::TemporarilyUnavailable => error::oauth_temporarily_unavailable(),
        OAuthError::ServerError => error::oauth_server_error(),
    }
}
