use axum::{
    extract::{
        Form, Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};

use super::{
    authorization::{
        AuthorizationRequest, AuthorizationRequestError, validate_authorization_request,
    },
    authorization_code_handlers::{
        authorization_quota_redirect, pending_from_validated, restore_pending_after_failure,
    },
    consent::PendingAuthorization,
    session::{SessionLookupError, session_for_headers},
};
use crate::{error, state::AppState};

pub use super::authorization_code_handlers::{
    AuthorizationCodeIssue, issue_authorization_code_result, validated_pending_request,
};

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Result<Query<AuthorizationRequest>, QueryRejection>,
) -> Response {
    let Query(request) = match request {
        Ok(request) => request,
        Err(_) => {
            return error::oauth_bad_request("invalid_request", "authorization request is invalid");
        }
    };
    authorize_request(state, headers, request).await
}

pub async fn authorize_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<AuthorizationRequest>, FormRejection>,
) -> Response {
    let Form(request) = match form {
        Ok(form) => form,
        Err(_) => {
            return error::oauth_bad_request("invalid_request", "authorization request is invalid");
        }
    };
    authorize_request(state, headers, request).await
}

async fn authorize_request(
    state: AppState,
    headers: HeaderMap,
    request: AuthorizationRequest,
) -> Response {
    let Some(client) = (match state.clients.find_registered(&request.client_id).await {
        Ok(client) => client,
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load OAuth client");
            return error::oauth_temporarily_unavailable();
        }
    }) else {
        return error::oauth_bad_request("invalid_client", "client is invalid");
    };

    let validated = match validate_authorization_request(&client, request.clone()) {
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
        let pending = pending_from_validated(&validated, None);
        return save_and_redirect_to_login(&state, &pending).await;
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
    let pending = pending_from_validated(&validated, Some(session.token.clone()));

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

async fn save_and_redirect_to_login(state: &AppState, pending: &PendingAuthorization) -> Response {
    if let Err(response) = save_pending(state, pending).await {
        return response;
    }
    Redirect::to(&format!("/login?request_id={}", pending.request_id)).into_response()
}

async fn save_pending(state: &AppState, pending: &PendingAuthorization) -> Result<(), Response> {
    match state.authorization_requests.save_limited(pending).await {
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
        if let Some(state) = request.state.as_deref().filter(|state| !state.is_empty()) {
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
