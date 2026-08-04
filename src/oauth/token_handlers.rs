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
    response::{self, issue_token_response},
    session::active_user_id,
    token_security::{
        enforce_qps, enforce_source_qps, record_token_event, verify_client_credentials,
    },
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
    let source_ip = connect_info.map(|Extension(ConnectInfo(peer))| peer.ip().to_string());
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
    )
    .await;
    if response.status() != StatusCode::OK {
        compensate_authorization_code_exchange(&state, &code, &refresh.value).await;
    }
    response
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

async fn exchange_refresh_token(state: AppState, request: TokenRequest) -> Response {
    let Some(refresh_value) = request.refresh_token.as_deref() else {
        return error::oauth_bad_request("invalid_request", "refresh_token is required");
    };
    let Some(client_id) = request.client_id.as_deref() else {
        return error::oauth_invalid_client();
    };
    let refresh = match state.refresh_tokens.find(refresh_value).await {
        Ok(Some(refresh)) => refresh,
        Ok(None) => {
            if record_token_event(
                &state,
                None,
                "token_refresh_failure",
                Some(client_id),
                "invalid_token",
            )
            .await
            .is_err()
            {
                return error::oauth_server_error();
            }
            return error::oauth_bad_request("invalid_grant", "refresh token is invalid");
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve refresh token");
            return error::oauth_temporarily_unavailable();
        }
    };
    if refresh
        .validate(client_id, time::OffsetDateTime::now_utc())
        .is_err()
    {
        if record_token_event(
            &state,
            Some(&refresh.user_id),
            "token_refresh_failure",
            Some(client_id),
            "invalid_token",
        )
        .await
        .is_err()
        {
            return error::oauth_server_error();
        }
        return error::oauth_bad_request("invalid_grant", "refresh token is invalid");
    }
    match state
        .revocations
        .is_consent_revoked(&refresh.user_id, client_id)
        .await
    {
        Ok(true) => {
            return error::oauth_bad_request("invalid_grant", "refresh token is invalid");
        }
        Ok(false) => {}
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to check OAuth consent revocation");
            return error::oauth_temporarily_unavailable();
        }
    }
    let Ok(user_id) = refresh.user_id.parse::<crate::users::domain::UserId>() else {
        return error::oauth_bad_request("invalid_grant", "refresh token is invalid");
    };
    match state
        .consents
        .has_scopes(user_id, client_id, &refresh.scopes)
        .await
    {
        Ok(true) => {}
        Ok(false) => return error::oauth_bad_request("invalid_grant", "refresh token is invalid"),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to check refresh token consent");
            return error::oauth_temporarily_unavailable();
        }
    }
    match active_user_id(&state, &refresh.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return error::oauth_bad_request("invalid_grant", "refresh token is invalid"),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load refresh token user");
            return error::oauth_temporarily_unavailable();
        }
    }
    let scopes = match request.scope.as_deref() {
        Some(scope) => {
            let requested = scope
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if requested
                .iter()
                .any(|scope| !refresh.scopes.contains(scope))
            {
                return error::oauth_bad_request(
                    "invalid_scope",
                    "requested scope exceeds original grant",
                );
            }
            requested
        }
        None => refresh.scopes.clone(),
    };
    let next_refresh = RefreshToken::new(
        client_id.to_owned(),
        refresh.user_id.clone(),
        scopes.clone(),
    );
    let response = issue_token_response(
        &state,
        &refresh.user_id,
        client_id,
        &scopes,
        Some(next_refresh.value.clone()),
        None,
    )
    .await;
    if response.status() != StatusCode::OK {
        return response;
    }
    match state
        .refresh_tokens
        .rotate_if_matches(refresh_value, &refresh, &next_refresh)
        .await
    {
        Ok(true) => {
            if record_token_event(
                &state,
                Some(&refresh.user_id),
                "token_refresh",
                Some(client_id),
                "success",
            )
            .await
            .is_err()
            {
                if let Err(error_value) = state.refresh_tokens.remove(&next_refresh.value).await {
                    tracing::warn!(
                        error = %error_value,
                        "failed to compensate refresh token after audit persistence failure"
                    );
                }
                if let Err(error_value) = state.refresh_tokens.save(&refresh).await {
                    tracing::warn!(
                        error = %error_value,
                        "failed to restore previous refresh token after audit persistence failure"
                    );
                }
                return error::oauth_server_error();
            }
            response
        }
        Ok(false) => {
            if record_token_event(
                &state,
                Some(&refresh.user_id),
                "token_refresh_failure",
                Some(client_id),
                "token_race",
            )
            .await
            .is_err()
            {
                return error::oauth_server_error();
            }
            error::oauth_bad_request("invalid_grant", "refresh token is invalid")
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to atomically rotate refresh token");
            error::oauth_temporarily_unavailable()
        }
    }
}

fn verify_code_is_redeemable(code: &AuthorizationCode) -> Result<(), ()> {
    let mut code = code.clone();
    code.redeem_at(time::OffsetDateTime::now_utc())
        .map_err(|_| ())
}
