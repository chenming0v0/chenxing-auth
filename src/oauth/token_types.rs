use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Deserialize)]
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

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &self.code.as_ref().map(|_| "<redacted>"))
            .field("redirect_uri", &self.redirect_uri)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "code_verifier",
                &self.code_verifier.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OAuthError {
    #[error("OAuth request is invalid: {code}: {description}")]
    BadRequest {
        code: &'static str,
        description: &'static str,
    },
    #[error("client authentication failed")]
    InvalidClient,
    #[error("OAuth service is temporarily unavailable")]
    TemporarilyUnavailable,
    #[error("OAuth server error")]
    ServerError,
}

impl OAuthError {
    pub(super) fn bad_request(code: &'static str, description: &'static str) -> Self {
        Self::BadRequest { code, description }
    }

    pub(super) fn invalid_grant() -> Self {
        Self::bad_request("invalid_grant", "authorization code is invalid")
    }

    pub(super) fn invalid_authorization_grant() -> Self {
        Self::bad_request("invalid_grant", "authorization grant is invalid")
    }

    pub(super) fn temporarily_unavailable() -> Self {
        Self::TemporarilyUnavailable
    }

    pub(super) fn server_error() -> Self {
        Self::ServerError
    }

    pub(super) fn invalid_refresh_grant() -> Self {
        Self::bad_request("invalid_grant", "refresh token is invalid")
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RefreshExchangeError {
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    #[error("OAuth server error")]
    ServerError,
}
