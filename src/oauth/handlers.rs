use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};

use super::{
    authorization::{
        AuthorizationRequest, AuthorizationRequestError, ValidatedAuthorizationRequest,
        validate_authorization_request,
    },
    code::AuthorizationCode,
    consent::PendingAuthorization,
    quota::QuotaConsumeResult,
    session::{SessionLookupError, active_user_id, session_for_headers},
};
use crate::audit::AuditEvent;
use crate::{error, state::AppState};

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<AuthorizationRequest>,
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

pub enum AuthorizationCodeIssue {
    Redirect(String),
    QuotaExceeded,
}

pub async fn issue_authorization_code_result(
    state: &AppState,
    user_id: String,
    validated: ValidatedAuthorizationRequest,
) -> Result<AuthorizationCodeIssue, Response> {
    match active_user_id(state, &user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(error::oauth_unauthorized(
                "invalid_session",
                "the authenticated session is no longer valid",
                "Session realm=\"oauth\"",
            ));
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load OAuth authorization user");
            return Err(error::oauth_temporarily_unavailable());
        }
    }
    let Some(client) = state
        .clients
        .find_registered(&validated.client_id)
        .await
        .map_err(|error_value| {
            tracing::error!(error = %error_value, "failed to load OAuth client for quota");
            error::oauth_temporarily_unavailable()
        })?
    else {
        return Err(error::oauth_bad_request(
            "invalid_client",
            "client is invalid",
        ));
    };
    let quota_consumed = if let Some(owner_user_id) = client.owner_user_id {
        let effective = match state.plans.effective_plan_for_user(owner_user_id).await {
            Ok(effective) => effective,
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to load plan for OAuth authorization quota");
                return Err(error::oauth_temporarily_unavailable());
            }
        };
        let daily_limit = effective.plan.daily_auth_limit.max(0) as u64;
        let monthly_limit = effective
            .plan
            .monthly_auth_limit
            .map(|limit| limit.max(0) as u64);
        match state
            .oauth_quotas
            .consume_with_limits(&validated.client_id, Some(daily_limit), monthly_limit)
            .await
            .map_err(|error_value| {
                tracing::error!(error = %error_value, "failed to consume OAuth authorization quota");
                error::oauth_temporarily_unavailable()
            })?
        {
            QuotaConsumeResult::Allowed => true,
            QuotaConsumeResult::DailyExceeded | QuotaConsumeResult::MonthlyExceeded => {
                return Ok(AuthorizationCodeIssue::QuotaExceeded);
            }
        }
    } else {
        false
    };
    let client_id = validated.client_id.clone();
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
        refund_quota_if_consumed(state, &client_id, quota_consumed).await;
        tracing::error!(error = %store_error, "failed to store OAuth authorization code");
        return Err(error::oauth_temporarily_unavailable());
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
            refund_quota_if_consumed(state, &client_id, quota_consumed).await;
            tracing::error!(error = %parse_error, "validated redirect URI could not be parsed");
            return Err(error::oauth_server_error());
        }
    };
    redirect_uri
        .query_pairs_mut()
        .append_pair("code", &code.value)
        .append_pair("state", &state_value);

    Ok(AuthorizationCodeIssue::Redirect(redirect_uri.to_string()))
}

async fn refund_quota_if_consumed(state: &AppState, client_id: &str, consumed: bool) {
    if !consumed {
        return;
    }
    if let Err(error_value) = state.oauth_quotas.refund(client_id).await {
        tracing::warn!(
            client_id = %client_id,
            error = %error_value,
            "failed to refund OAuth authorization quota"
        );
    }
}

pub async fn issue_authorization_code(
    state: &AppState,
    user_id: String,
    validated: ValidatedAuthorizationRequest,
) -> Response {
    let pending = PendingAuthorization {
        request_id: uuid::Uuid::new_v4().to_string(),
        client_id: validated.client_id.clone(),
        redirect_uri: validated.redirect_uri.clone(),
        scope: validated.scopes.join(" "),
        state: validated.state.clone(),
        nonce: validated.nonce.clone(),
        code_challenge: validated.code_challenge.clone(),
        code_challenge_method: "S256".to_owned(),
        session_id: None,
    };
    match issue_authorization_code_result(state, user_id, validated).await {
        Ok(AuthorizationCodeIssue::Redirect(redirect)) => Redirect::to(&redirect).into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => authorization_quota_redirect(&pending),
        Err(response) => response,
    }
}

pub fn validated_pending_request(pending: PendingAuthorization) -> ValidatedAuthorizationRequest {
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
        owner_user_id: None,
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

fn pending_from_validated(
    request: &ValidatedAuthorizationRequest,
    session_id: Option<String>,
) -> PendingAuthorization {
    PendingAuthorization {
        request_id: uuid::Uuid::new_v4().to_string(),
        client_id: request.client_id.clone(),
        redirect_uri: request.redirect_uri.clone(),
        scope: request.scopes.join(" "),
        state: request.state.clone(),
        nonce: request.nonce.clone(),
        code_challenge: request.code_challenge.clone(),
        code_challenge_method: "S256".to_owned(),
        session_id,
    }
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

fn authorization_quota_redirect(pending: &PendingAuthorization) -> Response {
    let Some(mut redirect) = url::Url::parse(&pending.redirect_uri).ok() else {
        return error::oauth_server_error();
    };
    redirect
        .query_pairs_mut()
        .append_pair("error", "temporarily_unavailable")
        .append_pair(
            "error_description",
            "authorization is temporarily unavailable",
        )
        .append_pair("state", &pending.state);
    Redirect::to(redirect.as_str()).into_response()
}

async fn restore_pending_after_failure(state: &AppState, pending: &PendingAuthorization) {
    if let Err(store_error) = state.authorization_requests.save(pending).await {
        tracing::error!(error = %store_error, "failed to restore OAuth authorization request");
    }
}

fn session_error_response(error_value: SessionLookupError) -> Response {
    tracing::error!(error = %error_value, "OAuth session lookup failed");
    error::oauth_temporarily_unavailable()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{StatusCode, header::LOCATION};

    fn client() -> super::super::authorization::RegisteredClient {
        super::super::authorization::RegisteredClient {
            client_id: "client-1".to_owned(),
            client_name: "Test Client".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            scopes: vec!["openid".to_owned()],
            owner_user_id: None,
        }
    }

    fn request(redirect_uri: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            client_id: "client-1".to_owned(),
            redirect_uri: redirect_uri.to_owned(),
            response_type: "code".to_owned(),
            scope: "openid".to_owned(),
            state: Some("state-1".to_owned()),
            nonce: None,
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        }
    }

    #[test]
    fn authorization_error_never_redirects_to_unregistered_uri() {
        let response = authorization_error(
            &request("https://attacker.example/callback"),
            &client(),
            AuthorizationRequestError::RedirectUriNotAllowed,
        );

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(LOCATION).is_none());
    }

    #[test]
    fn authorization_error_redirects_only_after_exact_uri_verification() {
        let mut request = request("https://client.example/callback");
        request.response_type = "token".to_owned();
        let response = authorization_error(
            &request,
            &client(),
            AuthorizationRequestError::UnsupportedResponseType,
        );

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("verified redirect location");
        assert!(location.contains("error=unsupported_response_type"));
        assert!(location.contains("state=state-1"));
    }
}
