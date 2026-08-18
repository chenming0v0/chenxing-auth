use crate::{
    api::extract::{RequestIssuer, SessionRead, SessionWrite},
    error,
    oauth::providers::{
        client_pkce::generate_code_verifier,
        domain::is_valid_provider_slug,
        service::{ExternalIdentityBindingError, ExternalOAuthError},
        state_store::{ExternalLoginState, ExternalLoginStateTake},
    },
    sessions::cookies,
    state::AppState,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::{BINDING_PURPOSE, binding_callback_path, binding_error, random_state};

async fn discard_binding_state(state: &AppState, state_value: &str, reason: &'static str) {
    if let Err(error_value) = state.external_login_states.discard(state_value).await {
        tracing::error!(
            error = %error_value,
            operation = "discard_external_identity_binding_state",
            reason,
            "failed to discard external identity binding state"
        );
    }
}

pub async fn start_external_binding(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    session: SessionWrite,
    Path(slug): Path<String>,
) -> Response {
    if !is_valid_provider_slug(&slug) {
        return error::not_found(
            "oauth_provider_not_found",
            "external OAuth provider not found",
        );
    }
    let provider = match state.external_oauth.find(&slug).await {
        Ok(provider) if provider.status == "active" && provider.claim_mapping().is_ok() => provider,
        _ => {
            return error::not_found(
                "oauth_provider_not_found",
                "external OAuth provider not found",
            );
        }
    };
    let Some(session_epoch) = session.session.credential_generation() else {
        return error::unauthorized("invalid_session", "user session is invalid");
    };
    let state_value = random_state();
    let code_verifier = if provider.pkce_enabled {
        generate_code_verifier()
    } else {
        String::new()
    };
    let pending = ExternalLoginState {
        state: state_value.clone(),
        provider_slug: slug.clone(),
        request_id: None,
        code_verifier: code_verifier.clone(),
        purpose: BINDING_PURPOSE.to_owned(),
        user_id: Some(session.user_id),
        session_id: Some(session.session.id),
        session_epoch: Some(session_epoch),
    };
    if let Err(error_value) = state.external_login_states.save(&pending).await {
        tracing::error!(error = %error_value, "failed to save external identity binding state");
        return error::internal();
    }
    let callback_uri = format!(
        "{}{}",
        issuer.issuer().as_str(),
        binding_callback_path(&slug)
    );
    let authorization_url = match state.external_oauth.authorization_url(
        &provider,
        &callback_uri,
        &state_value,
        &code_verifier,
    ) {
        Ok(url) => url,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load external OAuth security limits");
            discard_binding_state(&state, &state_value, "security_limits").await;
            return error::internal();
        }
    };
    let ttl = match state.settings.security_limits().await {
        Ok(limits) => limits.external_login_state_ttl_seconds,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load external OAuth security limits");
            discard_binding_state(&state, &state_value, "security_limits").await;
            return error::internal();
        }
    };
    let mut response = (
        StatusCode::OK,
        Json(BindingStartResponse { authorization_url }),
    )
        .into_response();
    if let Err(error_value) = cookies::append_external_state_cookie(
        response.headers_mut(),
        &state_value,
        ttl,
        state.config.cookie_secure,
    ) {
        tracing::error!(error = %error_value, "failed to append external identity binding state cookie");
        discard_binding_state(&state, &state_value, "cookie").await;
        return error::internal();
    }
    response
}

#[derive(Debug, Serialize)]
struct BindingStartResponse {
    authorization_url: String,
}

#[derive(Deserialize)]
pub struct BindingCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

impl fmt::Debug for BindingCallbackQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingCallbackQuery")
            .field("code", &self.code.as_ref().map(|_| "<redacted>"))
            .field("state", &self.state.as_ref().map(|_| "<redacted>"))
            .field("error", &self.error)
            .finish()
    }
}

pub async fn external_binding_callback(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    session: SessionRead,
    Path(slug): Path<String>,
    headers: axum::http::HeaderMap,
    Query(query): Query<BindingCallbackQuery>,
) -> Response {
    if !is_valid_provider_slug(&slug) {
        return error::not_found(
            "oauth_provider_not_found",
            "external OAuth provider not found",
        );
    }
    let Some(returned_state) = query.state.as_deref().filter(|value| !value.is_empty()) else {
        return error::bad_request("oauth_binding_failed", "external identity binding failed");
    };
    let cookie_matches =
        cookies::external_state(&headers, returned_state, state.config.cookie_secure)
            .ok()
            .flatten()
            .as_deref()
            == Some(returned_state);
    if !cookie_matches {
        return error::bad_request("oauth_binding_failed", "external identity binding failed");
    }
    let pending = match state
        .external_login_states
        .take_for_purpose_and_provider(returned_state, BINDING_PURPOSE, &slug)
        .await
    {
        Ok(ExternalLoginStateTake::Consumed(pending)) => pending,
        Ok(ExternalLoginStateTake::Mismatch) => {
            // Keep a valid state and its cookie when this callback was sent to a
            // different provider slug; the original callback may still complete.
            return error::bad_request(
                "oauth_binding_state_invalid",
                "external identity binding state is invalid or expired",
            );
        }
        Ok(ExternalLoginStateTake::MissingOrConsumed) => {
            return binding_error(
                &state,
                returned_state,
                "oauth_binding_state_invalid",
                "external identity binding state is invalid or expired",
            );
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to consume external identity binding state");
            return binding_error(
                &state,
                returned_state,
                "oauth_binding_failed",
                "external identity binding failed",
            );
        }
    };
    let (Some(user_id), Some(session_id), Some(session_epoch)) =
        (pending.user_id, pending.session_id, pending.session_epoch)
    else {
        return binding_error(
            &state,
            returned_state,
            "oauth_binding_state_invalid",
            "external identity binding state is invalid or expired",
        );
    };
    if session.user_id != user_id
        || session.session.id != session_id
        || session.session.credential_generation() != Some(session_epoch)
    {
        return binding_error(
            &state,
            returned_state,
            "oauth_binding_epoch_conflict",
            "the binding session is no longer current",
        );
    }
    if query.error.is_some() {
        return binding_error(
            &state,
            returned_state,
            "oauth_binding_failed",
            "external identity binding failed",
        );
    }
    let Some(code) = query.code.as_deref().filter(|value| !value.is_empty()) else {
        return binding_error(
            &state,
            returned_state,
            "oauth_binding_failed",
            "external identity binding failed",
        );
    };
    let provider = match state.external_oauth.find(&slug).await {
        Ok(provider) if provider.status == "active" => provider,
        _ => {
            return binding_error(
                &state,
                returned_state,
                "oauth_provider_not_found",
                "external OAuth provider not found",
            );
        }
    };
    let callback_uri = format!(
        "{}{}",
        issuer.issuer().as_str(),
        binding_callback_path(&slug)
    );
    let token = match state
        .external_oauth
        .exchange_code(&provider, &callback_uri, code, &pending.code_verifier)
        .await
    {
        Ok(token) => token,
        Err(_) => {
            return binding_error(
                &state,
                returned_state,
                "oauth_binding_failed",
                "external identity binding failed",
            );
        }
    };
    let external = match state.external_oauth.userinfo(&provider, &token).await {
        Ok(external) => external,
        Err(ExternalOAuthError::EmailNotVerified) => {
            return binding_error(
                &state,
                returned_state,
                "oauth_email_unverified",
                "external email is not verified",
            );
        }
        Err(_) => {
            return binding_error(
                &state,
                returned_state,
                "oauth_binding_failed",
                "external identity binding failed",
            );
        }
    };
    match state
        .external_oauth
        .bind_identity(user_id, session_epoch, provider.id, &external)
        .await
    {
        Ok(()) => {
            state
                .audit
                .record_best_effort(crate::audit::AuditEvent::new(
                    "user".to_owned(),
                    Some(user_id.to_string()),
                    crate::audit::AuditAction::ExternalIdentityLink,
                    "external_identity".to_owned(),
                    Some(format!("{}:{}", slug, external.subject)),
                    serde_json::json!({"provider": slug}),
                ))
                .await;
            let mut response = Redirect::to("/settings/security?external=linked").into_response();
            if let Err(error_value) = cookies::append_clear_external_state_cookie(
                response.headers_mut(),
                returned_state,
                state.config.cookie_secure,
            ) {
                tracing::error!(error = %error_value, "failed to clear external identity binding state cookie");
                return error::internal();
            }
            response
        }
        Err(ExternalIdentityBindingError::AlreadyOwned) => binding_error(
            &state,
            returned_state,
            "oauth_identity_already_linked",
            "external identity is already linked",
        ),
        Err(ExternalIdentityBindingError::OwnedByAnotherUser) => binding_error(
            &state,
            returned_state,
            "oauth_identity_owned_by_another_user",
            "external identity is owned by another user",
        ),
        Err(ExternalIdentityBindingError::AuthenticationChanged) => binding_error(
            &state,
            returned_state,
            "oauth_binding_epoch_conflict",
            "the binding session is no longer current",
        ),
        Err(ExternalIdentityBindingError::EmailNotVerified) => binding_error(
            &state,
            returned_state,
            "oauth_email_unverified",
            "external email is not verified",
        ),
        Err(ExternalIdentityBindingError::Database(error_value)) => {
            tracing::error!(error = %error_value, "failed to persist external identity binding");
            binding_error(
                &state,
                returned_state,
                "oauth_binding_failed",
                "external identity binding failed",
            )
        }
    }
}
