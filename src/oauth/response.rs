use axum::{
    Json,
    http::{
        HeaderValue, StatusCode,
        header::{CACHE_CONTROL, PRAGMA},
    },
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::fmt;

use super::{
    id_token::{IdTokenProfile, issue_id_token_with_profile_at},
    session::active_user_id,
    token::issue_access_token_at,
};
use crate::{config::IssuerUrl, error, state::AppState};

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
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

/// Token issuance context from one authorization exchange.
pub struct TokenIssueParams<'a> {
    pub issuer: &'a IssuerUrl,
    pub user_id: &'a str,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    pub refresh_token: Option<String>,
    pub nonce: Option<&'a str>,
    /// `None` omits the `auth_time` claim from the ID Token.
    pub auth_time: Option<i64>,
}

impl fmt::Debug for TokenIssueParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenIssueParams")
            .field("issuer", &self.issuer)
            .field("user_id", &self.user_id)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("nonce", &self.nonce.map(|_| "<redacted>"))
            .field("auth_time", &self.auth_time)
            .finish()
    }
}

pub async fn issue_token_response(state: &AppState, params: TokenIssueParams<'_>) -> Response {
    with_no_store_headers(issue_token_response_inner(state, params).await)
}

pub fn with_no_store_headers(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn issue_token_response_inner(state: &AppState, params: TokenIssueParams<'_>) -> Response {
    if !state.keys.signing_ready() {
        tracing::error!("OAuth token signing is disabled until key synchronization recovers");
        return error::oauth_temporarily_unavailable();
    }
    match active_user_id(state, params.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error::oauth_bad_request("invalid_grant", "authorization grant is invalid");
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load token user");
            return error::oauth_temporarily_unavailable();
        }
    }
    let token = match issue_access_token_at(
        &state.keys,
        params.issuer.as_str(),
        params.user_id,
        params.client_id,
        params.scopes,
        state.config.access_token_ttl_seconds,
        state.clock.now(),
    ) {
        Ok(token) => token,
        Err(token_error) => {
            tracing::error!(error = %token_error, "failed to issue OAuth access token");
            return error::oauth_temporarily_unavailable();
        }
    };
    let id_token = match issue_id_token(state, &params).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token: token,
            token_type: "Bearer",
            expires_in: state.config.access_token_ttl_seconds,
            scope: params.scopes.join(" "),
            refresh_token: params.refresh_token,
            id_token,
        }),
    )
        .into_response()
}

async fn issue_id_token(
    state: &AppState,
    params: &TokenIssueParams<'_>,
) -> Result<Option<String>, Response> {
    if !params.scopes.iter().any(|scope| scope == "openid") {
        return Ok(None);
    }
    let Ok(subject) = params.user_id.parse::<crate::users::domain::UserId>() else {
        tracing::error!(
            user_id = params.user_id,
            "cannot issue ID token for invalid user id"
        );
        return Err(error::oauth_temporarily_unavailable());
    };
    let profile = match state.users.find_profile(subject).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return Err(error::oauth_temporarily_unavailable()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load ID token profile");
            return Err(error::oauth_temporarily_unavailable());
        }
    };
    let id_token = issue_id_token_with_profile_at(
        &state.keys,
        params.issuer.as_str(),
        params.user_id,
        params.client_id,
        IdTokenProfile {
            nonce: params.nonce,
            email: params
                .scopes
                .iter()
                .any(|scope| scope == "email")
                .then_some(profile.email.as_str()),
            name: params
                .scopes
                .iter()
                .any(|scope| scope == "profile")
                .then_some(profile.display_name.as_deref())
                .flatten(),
            auth_time: params.auth_time,
        },
        state.config.id_token_ttl_seconds,
        state.clock.now(),
    )
    .map(Some)
    .map_err(|token_error| {
        tracing::error!(error = %token_error, "failed to issue OIDC ID token");
        error::oauth_temporarily_unavailable()
    })?;
    Ok(id_token)
}
