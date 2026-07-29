use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    authorization::{AuthorizationRequest, validate_authorization_request},
    consent::{ConsentDecision, PendingAuthorization, parse_decision},
    handlers::{AuthorizationCodeIssue, issue_authorization_code_result},
};
use crate::{
    error,
    sessions::{cookies, domain::Session},
    state::AppState,
    users::domain::UserId,
};

const PENDING_REQUEST_TTL_SECONDS: u64 = 600;

#[derive(Debug, Serialize)]
struct PendingRequestResponse {
    request_id: String,
    client_id: String,
    client_name: String,
    redirect_host: String,
    scopes: Vec<String>,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct DecisionInput {
    pub decision: String,
}

#[derive(Debug, Serialize)]
struct DecisionResponse {
    decision: &'static str,
    redirect_to: String,
}

struct UserContext {
    user_id: UserId,
    session: Session,
}

pub async fn inspect_authorization_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Response {
    let Ok(context) = current_user(&state, &headers).await else {
        return error::unauthorized("login_required", "an authenticated session is required");
    };
    let Some(pending) = state
        .authorization_requests
        .find(&request_id)
        .await
        .ok()
        .flatten()
    else {
        return error::bad_request(
            "authorization_request_expired",
            "authorization request is expired",
        );
    };
    if pending.session_id.as_deref() != Some(context.session.token.as_str()) {
        return error::unauthorized(
            "invalid_session",
            "authorization request is not bound to this session",
        );
    }
    let Some(client) = (match state.clients.find_registered(&pending.client_id).await {
        Ok(client) => client,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load OAuth UI client");
            return error::internal();
        }
    }) else {
        return error::bad_request("invalid_client", "client is invalid");
    };
    let Ok(redirect) = url::Url::parse(&pending.redirect_uri) else {
        return error::bad_request("invalid_request", "authorization request is invalid");
    };
    (
        axum::http::StatusCode::OK,
        Json(PendingRequestResponse {
            request_id: pending.request_id,
            client_id: pending.client_id,
            client_name: client.client_name,
            redirect_host: redirect.host_str().unwrap_or_default().to_owned(),
            scopes: pending
                .scope
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            expires_in: PENDING_REQUEST_TTL_SECONDS,
        }),
    )
        .into_response()
}

pub async fn decide_authorization_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(input): Json<DecisionInput>,
) -> Response {
    let Ok(context) = current_user(&state, &headers).await else {
        return error::unauthorized("login_required", "an authenticated session is required");
    };
    if !csrf_valid(&headers, &context.session) {
        return error::bad_request("csrf_invalid", "CSRF token is invalid");
    }
    let Some(decision) = parse_decision(&input.decision) else {
        return error::bad_request("invalid_decision", "authorization decision is invalid");
    };
    let Some(pending) = state
        .authorization_requests
        .find(&request_id)
        .await
        .ok()
        .flatten()
    else {
        return error::bad_request(
            "authorization_request_expired",
            "authorization request is expired",
        );
    };
    if pending.session_id.as_deref() != Some(context.session.token.as_str()) {
        return error::unauthorized(
            "invalid_session",
            "authorization request is not bound to this session",
        );
    }
    if matches!(decision, ConsentDecision::Deny) {
        let Some(pending) = state
            .authorization_requests
            .take(&request_id)
            .await
            .ok()
            .flatten()
        else {
            return error::bad_request(
                "authorization_request_expired",
                "authorization request is expired",
            );
        };
        return match error_redirect(&pending) {
            Some(redirect_to) => (
                axum::http::StatusCode::OK,
                Json(DecisionResponse {
                    decision: "deny",
                    redirect_to,
                }),
            )
                .into_response(),
            None => error::bad_request("invalid_request", "authorization request is invalid"),
        };
    }
    let validated = match validated_pending(&state, &pending).await {
        Ok(validated) => validated,
        Err(response) => return response,
    };
    let Some(pending) = state
        .authorization_requests
        .take(&request_id)
        .await
        .ok()
        .flatten()
    else {
        return error::bad_request(
            "authorization_request_expired",
            "authorization request is expired",
        );
    };
    if let Err(error_value) = state
        .consents
        .save(context.user_id, &pending.client_id, &validated.scopes)
        .await
    {
        tracing::error!(error = %error_value, "failed to save JSON OAuth consent");
        return error::internal();
    }
    match issue_authorization_code_result(&state, context.user_id.to_string(), validated).await {
        Ok(AuthorizationCodeIssue::Redirect(redirect_to)) => (
            axum::http::StatusCode::OK,
            Json(DecisionResponse {
                decision: "approve",
                redirect_to,
            }),
        )
            .into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => error::too_many_requests(
            "oauth_quota_exceeded",
            "OAuth authorization quota has been exhausted",
        ),
        Err(response) => response,
    }
}

async fn validated_pending(
    state: &AppState,
    pending: &PendingAuthorization,
) -> Result<super::authorization::ValidatedAuthorizationRequest, Response> {
    let Some(client) = state
        .clients
        .find_registered(&pending.client_id)
        .await
        .map_err(|_| error::internal())?
    else {
        return Err(error::bad_request("invalid_client", "client is invalid"));
    };
    validate_authorization_request(
        &client,
        AuthorizationRequest {
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            response_type: "code".to_owned(),
            scope: pending.scope.clone(),
            state: Some(pending.state.clone()),
            nonce: pending.nonce.clone(),
            code_challenge: Some(pending.code_challenge.clone()),
            code_challenge_method: Some(pending.code_challenge_method.clone()),
        },
    )
    .map_err(|_| error::bad_request("invalid_request", "authorization request is invalid"))
}

fn error_redirect(pending: &PendingAuthorization) -> Option<String> {
    let mut redirect = url::Url::parse(&pending.redirect_uri).ok()?;
    redirect
        .query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("state", &pending.state);
    Some(redirect.to_string())
}

async fn current_user(state: &AppState, headers: &HeaderMap) -> Result<UserContext, Response> {
    let Some(session_token) = cookies::cookie_value_by_name(headers, cookies::SESSION_COOKIE)
    else {
        return Err(error::unauthorized(
            "login_required",
            "an authenticated session is required",
        ));
    };
    let Some(session) = state
        .sessions
        .find(&session_token)
        .await
        .map_err(|_| error::internal())?
    else {
        return Err(error::unauthorized(
            "invalid_session",
            "user session is invalid",
        ));
    };
    if !session.is_active() {
        return Err(error::unauthorized(
            "invalid_session",
            "user session is invalid",
        ));
    }
    let user_id = session
        .user_id
        .parse::<UserId>()
        .map_err(|_| error::unauthorized("invalid_session", "user session is invalid"))?;
    Ok(UserContext { user_id, session })
}

fn csrf_valid(headers: &HeaderMap, session: &Session) -> bool {
    let Some(cookie) = cookies::csrf_cookie(headers) else {
        return false;
    };
    let Some(header) = cookies::csrf_token(headers) else {
        return false;
    };
    cookie == header && session.validates_csrf(&header)
}
