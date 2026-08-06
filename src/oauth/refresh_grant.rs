//! HTTP adapter for the `grant_type=refresh_token` flow.

use axum::{Json, response::{IntoResponse, Response}};

use super::{
    token_handlers::TokenRequest,
    token_use_case::{self, OAuthError, RefreshExchangeError},
};
use crate::{error, state::AppState};

/// Handle a refresh-token request after `token_inner` has authenticated the client.
pub async fn exchange_refresh_token(state: AppState, request: TokenRequest) -> Response {
    match token_use_case::exchange_refresh_token(&state, request).await {
        Ok(token) => Json(token).into_response(),
        Err(error_value) => oauth_error_response(error_value),
    }
}

fn oauth_error_response(error_value: RefreshExchangeError) -> Response {
    match error_value {
        RefreshExchangeError::OAuth(OAuthError::BadRequest { code, description }) => {
            error::oauth_bad_request(code, description)
        }
        RefreshExchangeError::OAuth(OAuthError::InvalidClient) => error::oauth_invalid_client(),
        RefreshExchangeError::OAuth(OAuthError::TemporarilyUnavailable) => {
            error::oauth_temporarily_unavailable()
        }
        RefreshExchangeError::ServerError => error::oauth_server_error(),
    }
}
