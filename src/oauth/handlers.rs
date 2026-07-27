use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};

use super::{
    authorization::{
        AuthorizationRequest, ValidatedAuthorizationRequest, validate_authorization_request,
    },
    code::AuthorizationCode,
    session::session_user_id,
};
use crate::audit::AuditEvent;
use crate::{error, state::AppState};

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<AuthorizationRequest>,
) -> Response {
    let user_id = session_user_id(&state, &headers).await;
    if user_id.is_none() {
        if !accepts_html(&headers) {
            return error::unauthorized("login_required", "an authenticated session is required");
        }
        let pending = match pending_from_browser_request(&request) {
            Ok(pending) => pending,
            Err(message) => return error::bad_request("invalid_request", message),
        };
        let request_id = pending.request_id.clone();
        if let Err(store_error) = state.authorization_requests.save(&pending).await {
            tracing::error!(error = %store_error, "failed to store browser authorization request");
            return error::internal();
        }
        return Redirect::to(&format!("/auth/login?request_id={request_id}")).into_response();
    }

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

    let user_id = user_id.expect("checked above");

    if headers.get("cookie").is_some() && accepts_html(&headers) {
        let scopes = validated.scopes.clone();
        let user_uuid = match uuid::Uuid::parse_str(&user_id) {
            Ok(user_uuid) => user_uuid,
            Err(_) => return error::unauthorized("invalid_session", "session user is invalid"),
        };
        match state
            .consents
            .has_scopes(user_uuid, &validated.client_id, &scopes)
            .await
        {
            Ok(true) => {}
            Ok(false) if accepts_html(&headers) => {
                let request_id = uuid::Uuid::new_v4().to_string();
                let pending = super::consent::PendingAuthorization {
                    request_id: request_id.clone(),
                    client_id: validated.client_id,
                    redirect_uri: validated.redirect_uri,
                    scope: validated.scopes.join(" "),
                    state: validated.state,
                    nonce: validated.nonce,
                    code_challenge: validated.code_challenge,
                    code_challenge_method: "S256".to_owned(),
                };
                if let Err(store_error) = state.authorization_requests.save(&pending).await {
                    tracing::error!(error = %store_error, "failed to store consent request");
                    return error::internal();
                }
                return Redirect::to(&format!("/oauth/authorize/consent?request_id={request_id}"))
                    .into_response();
            }
            Ok(false) => {
                return error::unauthorized(
                    "consent_required",
                    "authorization consent is required",
                );
            }
            Err(database_error) => {
                tracing::error!(error = %database_error, "failed to load user consent");
                return error::internal();
            }
        }
    }

    issue_authorization_code(&state, user_id, validated).await
}

pub async fn issue_authorization_code(
    state: &AppState,
    user_id: String,
    validated: ValidatedAuthorizationRequest,
) -> Response {
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

pub fn validated_pending_request(
    pending: super::consent::PendingAuthorization,
) -> ValidatedAuthorizationRequest {
    ValidatedAuthorizationRequest {
        client_id: pending.client_id,
        redirect_uri: pending.redirect_uri,
        scopes: pending
            .scope
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        state: pending.state,
        nonce: pending.nonce,
        code_challenge: pending.code_challenge,
    }
}

pub use super::token_handlers::token;

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

fn pending_from_browser_request(
    request: &AuthorizationRequest,
) -> Result<super::consent::PendingAuthorization, &'static str> {
    if request.client_id.trim().is_empty() || request.response_type != "code" {
        return Err("authorization request is invalid");
    }
    let redirect = url::Url::parse(&request.redirect_uri).map_err(|_| "redirect URI is invalid")?;
    if redirect.scheme() != "https"
        || redirect.host_str().is_none()
        || redirect.fragment().is_some()
    {
        return Err("redirect URI is invalid");
    }
    let state = request
        .state
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or("state is required")?;
    if request.scope.split_whitespace().next().is_none()
        || request.code_challenge_method.as_deref() != Some("S256")
        || request.code_challenge.as_deref().is_none_or(str::is_empty)
    {
        return Err("authorization request is invalid");
    }
    Ok(super::consent::PendingAuthorization {
        request_id: uuid::Uuid::new_v4().to_string(),
        client_id: request.client_id.clone(),
        redirect_uri: request.redirect_uri.clone(),
        scope: request.scope.clone(),
        state: state.to_owned(),
        nonce: request
            .nonce
            .clone()
            .filter(|value| !value.trim().is_empty()),
        code_challenge: request.code_challenge.clone().expect("checked above"),
        code_challenge_method: "S256".to_owned(),
    })
}
