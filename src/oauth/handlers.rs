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
    quota::QuotaConsumeResult,
    session::{active_user_id, session_user_id},
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
            if record_authorization_event(&state, None, "authorization_denied", "login_required")
                .await
                .is_err()
            {
                return error::internal();
            }
            return error::unauthorized("login_required", "an authenticated session is required");
        }
        let pending = match pending_from_browser_request(&request) {
            Ok(pending) => pending,
            Err(message) => {
                if record_authorization_event(
                    &state,
                    None,
                    "authorization_denied",
                    "invalid_request",
                )
                .await
                .is_err()
                {
                    return error::internal();
                }
                return error::bad_request("invalid_request", message);
            }
        };
        let request_id = pending.request_id.clone();
        if let Err(store_error) = state.authorization_requests.save(&pending).await {
            tracing::error!(error = %store_error, "failed to store browser authorization request");
            return error::internal();
        }
        // Hand off to the React SPA login page. It logs in over JSON, binds the
        // session to this pending request, then continues to the consent screen.
        // (`/oauth/authorize` itself is owned by this backend handler, so we must
        // redirect to an SPA-served path instead.)
        return Redirect::to(&format!("/login?request_id={request_id}")).into_response();
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
            if record_authorization_event(&state, None, "authorization_denied", "invalid_request")
                .await
                .is_err()
            {
                return error::internal();
            }
            return error::bad_request("invalid_request", "authorization request is invalid");
        }
    };

    let user_id = user_id.expect("checked above");

    if headers.get("cookie").is_some() && accepts_html(&headers) {
        let scopes = validated.scopes.clone();
        let user_id = match user_id.parse::<crate::users::domain::UserId>() {
            Ok(user_id) => user_id,
            Err(_) => return error::unauthorized("invalid_session", "session user is invalid"),
        };
        match state
            .consents
            .has_scopes(user_id, &validated.client_id, &scopes)
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
                    session_id: Some(
                        super::session::session_for_headers(&state, &headers)
                            .await
                            .expect("authenticated session")
                            .token,
                    ),
                };
                if let Err(store_error) = state.authorization_requests.save(&pending).await {
                    tracing::error!(error = %store_error, "failed to store consent request");
                    return error::internal();
                }
                return Redirect::to(&format!("/oauth/consent?request_id={request_id}"))
                    .into_response();
            }
            Ok(false) => {
                let actor_id = user_id.to_string();
                if record_authorization_event(
                    &state,
                    Some(&actor_id),
                    "authorization_denied",
                    "consent_required",
                )
                .await
                .is_err()
                {
                    return error::internal();
                }
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
            if record_authorization_event(
                state,
                Some(&user_id),
                "authorization_denied",
                "user_disabled",
            )
            .await
            .is_err()
            {
                return Err(error::internal());
            }
            return Err(error::unauthorized(
                "user_disabled",
                "user account is disabled",
            ));
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load OAuth authorization user");
            return Err(error::internal());
        }
    }
    let Some(client) = state
        .clients
        .find_registered(&validated.client_id)
        .await
        .map_err(|error_value| {
            tracing::error!(error = %error_value, "failed to load OAuth client for quota");
            error::internal()
        })?
    else {
        return Err(error::bad_request("invalid_client", "client is invalid"));
    };
    let quota_consumed = if let Some(owner_user_id) = client.owner_user_id {
        let effective = match state.plans.effective_plan_for_user(owner_user_id).await {
            Ok(effective) => effective,
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to load plan for OAuth authorization quota");
                return Err(error::internal());
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
                error::internal()
            })?
        {
            QuotaConsumeResult::Allowed => true,
            QuotaConsumeResult::DailyExceeded | QuotaConsumeResult::MonthlyExceeded => {
                if record_authorization_event(
                    state,
                    Some(&user_id),
                    "rate_limit_triggered",
                    "oauth_quota",
                )
                .await
                .is_err()
                {
                    return Err(error::internal());
                }
                return Ok(AuthorizationCodeIssue::QuotaExceeded)
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
        return Err(error::internal());
    }
    if state
        .audit
        .record(AuditEvent::new(
            "user".to_owned(),
            Some(code.user_id.clone()),
            "authorization_code_issue".to_owned(),
            "oauth_client".to_owned(),
            Some(code.client_id.clone()),
            serde_json::json!({"scopes": code.scopes}),
        ))
        .await
        .is_err()
    {
        if let Err(error_value) = state.authorization_codes.take(&code.value).await {
            tracing::warn!(
                error = %error_value,
                "failed to compensate authorization code after audit persistence failure"
            );
        }
        refund_quota_if_consumed(state, &client_id, quota_consumed).await;
        return Err(error::internal());
    }

    let mut redirect_uri = match url::Url::parse(&validated.redirect_uri) {
        Ok(uri) => uri,
        Err(parse_error) => {
            refund_quota_if_consumed(state, &client_id, quota_consumed).await;
            tracing::error!(error = %parse_error, "validated redirect URI could not be parsed");
            return Err(error::internal());
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
    let state_value = validated.state.clone();
    let redirect_uri = validated.redirect_uri.clone();
    match issue_authorization_code_result(state, user_id, validated).await {
        Ok(AuthorizationCodeIssue::Redirect(redirect)) => Redirect::to(&redirect).into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => {
            let mut redirect = match url::Url::parse(&redirect_uri) {
                Ok(redirect) => redirect,
                Err(_) => return error::internal(),
            };
            redirect
                .query_pairs_mut()
                .append_pair("error", "temporarily_unavailable")
                .append_pair("error_description", "OAuth authorization quota exceeded")
                .append_pair("state", &state_value);
            Redirect::to(redirect.as_str()).into_response()
        }
        Err(response) => response,
    }
}

async fn record_authorization_event(
    state: &AppState,
    actor_id: Option<&str>,
    action: &str,
    reason: &str,
) -> Result<(), crate::audit::AuditError> {
    state
        .audit
        .record(AuditEvent::new(
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "anonymous".to_owned()
            },
            actor_id.map(str::to_owned),
            action.to_owned(),
            "oauth_authorization".to_owned(),
            None,
            serde_json::json!({"reason": reason}),
        ))
        .await
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
        session_id: None,
    })
}
