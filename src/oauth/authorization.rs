use super::pkce::validate_s256_challenge;
use crate::users::domain::UserId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub owner_user_id: Option<UserId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub owner_user_id: Option<UserId>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationRequestError {
    #[error("client id is invalid")]
    InvalidClient,
    #[error("redirect URI is not registered")]
    RedirectUriNotAllowed,
    #[error("response type must be code")]
    UnsupportedResponseType,
    #[error("requested scope is not allowed")]
    ScopeNotAllowed,
    #[error("state is required")]
    MissingState,
    #[error("PKCE S256 is required")]
    PkceRequired,
    #[error("PKCE S256 challenge is invalid")]
    InvalidCodeChallenge,
}

pub fn validate_authorization_request(
    client: &RegisteredClient,
    request: AuthorizationRequest,
) -> Result<ValidatedAuthorizationRequest, AuthorizationRequestError> {
    if request.client_id != client.client_id {
        return Err(AuthorizationRequestError::InvalidClient);
    }
    if !client
        .redirect_uris
        .iter()
        .any(|uri| uri == &request.redirect_uri)
    {
        return Err(AuthorizationRequestError::RedirectUriNotAllowed);
    }
    if request.response_type != "code" {
        return Err(AuthorizationRequestError::UnsupportedResponseType);
    }
    let scopes = request
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if scopes.is_empty() || scopes.iter().any(|scope| !client.scopes.contains(scope)) {
        return Err(AuthorizationRequestError::ScopeNotAllowed);
    }
    let state = request
        .state
        .filter(|state| !state.trim().is_empty())
        .ok_or(AuthorizationRequestError::MissingState)?;
    if request.code_challenge_method.as_deref() != Some("S256") {
        return Err(AuthorizationRequestError::PkceRequired);
    }
    let Some(code_challenge) = request.code_challenge.as_deref() else {
        return Err(AuthorizationRequestError::PkceRequired);
    };
    if validate_s256_challenge(code_challenge).is_err() {
        return Err(AuthorizationRequestError::InvalidCodeChallenge);
    }

    Ok(ValidatedAuthorizationRequest {
        client_id: request.client_id,
        redirect_uri: request.redirect_uri,
        scopes,
        state,
        nonce: request.nonce.filter(|nonce| !nonce.trim().is_empty()),
        code_challenge: code_challenge.to_owned(),
        owner_user_id: Some(client.owner_user_id).flatten(),
    })
}
