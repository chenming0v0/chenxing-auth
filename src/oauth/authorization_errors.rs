use axum::{
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};

use super::{
    authorization::{
        AuthorizationRequest, AuthorizationRequestError, MAX_STATE_LENGTH, redirect_uri_matches,
    },
    consent::PendingAuthorization,
    session::SessionLookupError,
};
use crate::{clients::domain::canonicalize_redirect_uri, error};

pub(super) fn accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|item| item.trim().starts_with("text/html"))
        })
}

pub(super) fn authorization_error(
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
        AuthorizationRequestError::InvalidPrompt => ("invalid_request", "prompt is invalid"),
        AuthorizationRequestError::PromptNoneCombined => (
            "invalid_request",
            "prompt=none cannot be combined with another prompt value",
        ),
        AuthorizationRequestError::MaxAgeTooLarge => ("invalid_request", "max_age is too large"),
        AuthorizationRequestError::PkceRequired => ("invalid_request", "PKCE S256 is required"),
        AuthorizationRequestError::InvalidCodeChallenge => {
            ("invalid_request", "code_challenge is invalid")
        }
    };
    authorization_error_redirect(request, client, code, description)
}

pub(super) fn authorization_error_redirect(
    request: &AuthorizationRequest,
    client: &super::authorization::RegisteredClient,
    code: &'static str,
    description: &str,
) -> Response {
    if let Some(canonical_redirect_uri) = canonicalize_redirect_uri(&request.redirect_uri)
        && client
            .redirect_uris
            .iter()
            .any(|registered| redirect_uri_matches(registered, &canonical_redirect_uri))
        && let Ok(mut redirect) = url::Url::parse(&canonical_redirect_uri)
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

pub(super) fn trusted_pending_error(
    pending: &PendingAuthorization,
    client: &super::authorization::RegisteredClient,
    code: &'static str,
    description: &str,
) -> Response {
    let request = AuthorizationRequest {
        client_id: pending.client_id.clone(),
        redirect_uri: pending.redirect_uri.clone(),
        response_type: "code".to_owned(),
        scope: pending.scope.clone(),
        state: Some(pending.state.clone()),
        nonce: pending.nonce.clone(),
        code_challenge: Some(pending.code_challenge.clone()),
        code_challenge_method: Some(pending.code_challenge_method.clone()),
        prompt: pending.prompt.clone(),
        max_age: pending.max_age,
    };
    authorization_error_redirect(&request, client, code, description)
}

pub(super) fn authorization_dependency_error(
    request: &AuthorizationRequest,
    client: &super::authorization::RegisteredClient,
    code: &'static str,
    description: &str,
) -> Response {
    authorization_error_redirect(request, client, code, description)
}

pub(super) fn session_error_code(error_value: SessionLookupError) -> (&'static str, &'static str) {
    tracing::error!(error = %error_value, "OAuth session lookup failed");
    (
        "temporarily_unavailable",
        "the authorization server is temporarily unable to handle the request",
    )
}
