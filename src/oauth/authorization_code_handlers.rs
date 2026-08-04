use axum::response::{IntoResponse, Redirect, Response};
use std::fmt;

use super::{
    authorization::ValidatedAuthorizationRequest,
    code::AuthorizationCode,
    consent::PendingAuthorization,
    quota::QuotaConsumeResult,
    session::active_user_id,
};
use crate::audit::AuditEvent;
use crate::{error, state::AppState};

pub enum AuthorizationCodeIssue {
    Redirect(String),
    QuotaExceeded,
}

impl fmt::Debug for AuthorizationCodeIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redirect(_) => formatter
                .debug_tuple("AuthorizationCodeIssue::Redirect")
                .field(&"<redacted>")
                .finish(),
            Self::QuotaExceeded => formatter.write_str("AuthorizationCodeIssue::QuotaExceeded"),
        }
    }
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
                return Err(error::oauth_server_error());
            }
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
    let client_id = validated.client_id.clone();
    let code = AuthorizationCode::new_with_nonce(
        validated.client_id,
        validated.redirect_uri.clone(),
        user_id.clone(),
        validated.scopes,
        validated.code_challenge,
        validated.nonce,
    );
    let state_value = validated.state;
    if let Err(store_error) = state.authorization_codes.save(&code).await {
        tracing::error!(error = %store_error, "failed to store OAuth authorization code");
        return Err(error::oauth_temporarily_unavailable());
    }
    if let Err(error_value) = state
        .revocations
        .clear_consent(&code.user_id, &code.client_id)
        .await
    {
        tracing::error!(error = %error_value, "failed to clear OAuth consent revocation marker");
        remove_authorization_code_after_failure(state, &code, &client_id, false).await;
        return Err(error::oauth_temporarily_unavailable());
    }

    let quota_consumed = if let Some(owner_user_id) = client.owner_user_id {
        let effective = match state.plans.effective_plan_for_user(owner_user_id).await {
            Ok(effective) => effective,
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to load plan for OAuth authorization quota");
                remove_authorization_code_after_failure(state, &code, &client_id, false).await;
                return Err(error::oauth_temporarily_unavailable());
            }
        };
        let limits = effective.plan.auth_quota_limits();
        let consume_result = match state
            .oauth_quotas
            .consume_with_limits(&client_id, limits)
            .await
        {
            Ok(result) => result,
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to consume OAuth authorization quota");
                remove_authorization_code_after_failure(state, &code, &client_id, false).await;
                return Err(error::oauth_temporarily_unavailable());
            }
        };
        match consume_result {
            QuotaConsumeResult::Allowed => true,
            QuotaConsumeResult::DailyExceeded | QuotaConsumeResult::MonthlyExceeded => {
                remove_authorization_code_after_failure(state, &code, &client_id, false).await;
                if record_authorization_event(
                    state,
                    Some(&user_id),
                    "rate_limit_triggered",
                    "oauth_quota",
                )
                .await
                .is_err()
                {
                    return Err(error::oauth_server_error());
                }
                return Ok(AuthorizationCodeIssue::QuotaExceeded);
            }
        }
    } else {
        false
    };
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
        remove_authorization_code_after_failure(state, &code, &client_id, quota_consumed).await;
        return Err(error::oauth_server_error());
    }

    let mut redirect_uri = match url::Url::parse(&validated.redirect_uri) {
        Ok(uri) => uri,
        Err(parse_error) => {
            remove_authorization_code_after_failure(state, &code, &client_id, quota_consumed).await;
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

async fn remove_authorization_code_after_failure(
    state: &AppState,
    code: &AuthorizationCode,
    client_id: &str,
    quota_consumed: bool,
) {
    if let Err(error_value) = state.authorization_codes.take(&code.value).await {
        tracing::warn!(
            error = %error_value,
            "failed to compensate authorization code after authorization failure"
        );
    }
    refund_quota_if_consumed(state, client_id, quota_consumed).await;
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

pub(crate) fn authorization_quota_redirect(pending: &PendingAuthorization) -> Response {
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

pub(crate) fn pending_from_validated(
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

pub(crate) async fn restore_pending_after_failure(
    state: &AppState,
    pending: &PendingAuthorization,
) {
    if let Err(store_error) = state.authorization_requests.save(pending).await {
        tracing::error!(error = %store_error, "failed to restore OAuth authorization request");
    }
}

pub async fn issue_authorization_code(
    state: &AppState,
    user_id: String,
    validated: ValidatedAuthorizationRequest,
) -> Response {
    let pending = pending_from_validated(&validated, None);
    match issue_authorization_code_result(state, user_id, validated).await {
        Ok(AuthorizationCodeIssue::Redirect(redirect)) => Redirect::to(&redirect).into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => authorization_quota_redirect(&pending),
        Err(response) => response,
    }
}
