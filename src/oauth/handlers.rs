use axum::{
    extract::{Form, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use super::{
    authorization::{AuthorizationRequest, validate_authorization_request},
    code::AuthorizationCode,
    pkce::verify_s256,
    refresh::RefreshToken,
    response::issue_token_response,
    session::session_user_id,
};
use crate::audit::AuditEvent;
use crate::{error, state::AppState};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<AuthorizationRequest>,
) -> Response {
    let Some(user_id) = session_user_id(&state, &headers).await else {
        return error::unauthorized("login_required", "an authenticated session is required");
    };

    let Some(client) = (match state.clients.find_registered(&request.client_id).await {
        Ok(client) => client,
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load OAuth client");
            return error::internal();
        }
    }) else {
        return error::bad_request("invalid_client", "client is invalid");
    };

    let validated = match validate_authorization_request(&client, request) {
        Ok(request) => request,
        Err(validation_error) => {
            tracing::info!(error = %validation_error, "OAuth authorization request rejected");
            return error::bad_request("invalid_request", "authorization request is invalid");
        }
    };

    let code = AuthorizationCode::new_with_nonce(
        validated.client_id,
        validated.redirect_uri.clone(),
        user_id,
        validated.scopes,
        validated.code_challenge,
        validated.nonce,
    );
    let state_value = validated.state;
    if let Err(store_error) = state.authorization_codes.save(&code).await {
        tracing::error!(error = %store_error, "failed to store OAuth authorization code");
        return error::internal();
    }
    state
        .audit
        .record(AuditEvent::new(
            "user".to_owned(),
            Some(code.user_id.clone()),
            "authorization_code_issue".to_owned(),
            "oauth_client".to_owned(),
            Some(code.client_id.clone()),
            serde_json::json!({"scopes": code.scopes}),
        ))
        .await;

    let mut redirect_uri = match url::Url::parse(&validated.redirect_uri) {
        Ok(uri) => uri,
        Err(parse_error) => {
            tracing::error!(error = %parse_error, "validated redirect URI could not be parsed");
            return error::internal();
        }
    };
    redirect_uri
        .query_pairs_mut()
        .append_pair("code", &code.value)
        .append_pair("state", &state_value);

    Redirect::to(redirect_uri.as_str()).into_response()
}

pub async fn token(State(state): State<AppState>, Form(request): Form<TokenRequest>) -> Response {
    match request.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(state, request).await,
        "refresh_token" => exchange_refresh_token(state, request).await,
        _ => error::bad_request("unsupported_grant_type", "grant type is unsupported"),
    }
}

async fn exchange_authorization_code(state: AppState, request: TokenRequest) -> Response {
    if let Some(response) = verify_client_credentials(&state, &request).await {
        return response;
    }
    let Some(code_value) = request.code.as_deref() else {
        return error::bad_request("invalid_request", "code is required");
    };
    let Some(redirect_uri) = request.redirect_uri.as_deref() else {
        return error::bad_request("invalid_request", "redirect_uri is required");
    };
    let Some(code_verifier) = request.code_verifier.as_deref() else {
        return error::bad_request("invalid_request", "code_verifier is required");
    };
    let code = match state.authorization_codes.find(code_value).await {
        Ok(Some(code)) => code,
        Ok(None) => return error::bad_request("invalid_grant", "authorization code is invalid"),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve OAuth authorization code");
            return error::internal();
        }
    };
    if code.client_id != request.client_id || code.redirect_uri != redirect_uri {
        return error::bad_request("invalid_grant", "authorization code binding is invalid");
    }
    if let Err(code_error) = verify_code_is_redeemable(&code) {
        return error::bad_request("invalid_grant", code_error);
    }
    if let Err(pkce_error) = verify_s256(code_verifier, &code.code_challenge) {
        tracing::info!(error = %pkce_error, "OAuth PKCE verification failed");
        return error::bad_request("invalid_grant", "PKCE verification failed");
    }
    match state
        .authorization_codes
        .take_if_matches(code_value, &code)
        .await
    {
        Ok(true) => {}
        Ok(false) => return error::bad_request("invalid_grant", "authorization code is invalid"),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to consume OAuth authorization code");
            return error::internal();
        }
    }

    let refresh = RefreshToken::new_with_nonce(
        request.client_id.clone(),
        code.user_id.clone(),
        code.scopes.clone(),
        code.nonce.clone(),
    );
    if let Err(store_error) = state.refresh_tokens.save(&refresh).await {
        tracing::error!(error = %store_error, "failed to store refresh token");
        return error::internal();
    }
    issue_token_response(
        &state,
        &code.user_id,
        &request.client_id,
        &code.scopes,
        Some(refresh.value),
        code.nonce.as_deref(),
    )
    .await
}

async fn exchange_refresh_token(state: AppState, request: TokenRequest) -> Response {
    if let Some(response) = verify_client_credentials(&state, &request).await {
        return response;
    }
    let Some(refresh_value) = request.refresh_token.as_deref() else {
        return error::bad_request("invalid_request", "refresh_token is required");
    };
    let refresh = match state.refresh_tokens.find(refresh_value).await {
        Ok(Some(refresh)) => refresh,
        Ok(None) => return error::bad_request("invalid_grant", "refresh token is invalid"),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve refresh token");
            return error::internal();
        }
    };
    if let Err(refresh_error) =
        refresh.validate(&request.client_id, time::OffsetDateTime::now_utc())
    {
        return error::bad_request("invalid_grant", refresh_error.to_string());
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
                return error::bad_request(
                    "invalid_scope",
                    "requested scope exceeds original grant",
                );
            }
            requested
        }
        None => refresh.scopes.clone(),
    };
    match state
        .refresh_tokens
        .take_if_matches(refresh_value, &refresh)
        .await
    {
        Ok(true) => {}
        Ok(false) => return error::bad_request("invalid_grant", "refresh token is invalid"),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to consume refresh token");
            return error::internal();
        }
    }
    let next_refresh = RefreshToken::new_with_nonce(
        request.client_id.clone(),
        refresh.user_id.clone(),
        scopes.clone(),
        refresh.nonce.clone(),
    );
    if let Err(store_error) = state.refresh_tokens.save(&next_refresh).await {
        tracing::error!(error = %store_error, "failed to rotate refresh token");
        return error::internal();
    }
    issue_token_response(
        &state,
        &refresh.user_id,
        &request.client_id,
        &scopes,
        Some(next_refresh.value),
        refresh.nonce.as_deref(),
    )
    .await
}

async fn verify_client_credentials(state: &AppState, request: &TokenRequest) -> Option<Response> {
    match state
        .clients
        .verify_credentials(&request.client_id, &request.client_secret)
        .await
    {
        Ok(true) => None,
        Ok(false) => Some(error::unauthorized(
            "invalid_client",
            "client credentials are invalid",
        )),
        Err(client_error) => {
            tracing::error!(error = %client_error, "failed to verify OAuth client credentials");
            Some(error::internal())
        }
    }
}

fn verify_code_is_redeemable(code: &AuthorizationCode) -> Result<(), &'static str> {
    let mut code = code.clone();
    code.redeem_at(time::OffsetDateTime::now_utc())
        .map_err(|_| "authorization code is expired or already redeemed")
}
