//! Authorization-decision application use case, independent of Axum types.

use std::fmt;

use super::{
    authorization::{
        AuthorizationRequest, RegisteredClient, ValidatedAuthorizationRequest,
        redirect_uri_matches, validate_authorization_request_with_allowlist,
    },
    authorization_code_handlers::{AuthorizationCodeIssue, issue_authorization_code_result},
    consent::{ConsentDecision, PendingAuthorization},
    request_store::ConsumedPendingAuthorization,
    session::active_user_id,
};
use crate::{
    audit::AuditEvent, clients::domain::canonicalize_redirect_uri, consents::ConsentServiceError,
    sessions::domain::session_token_hash, settings::IssuerSnapshot, state::AppState,
    users::domain::UserId,
};

#[derive(Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Approved { redirect_to: String },
    Denied { redirect_to: String },
}

impl fmt::Debug for AuthorizationDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved { .. } => formatter
                .debug_struct("Approved")
                .field("redirect_to", &"<redacted>")
                .finish(),
            Self::Denied { .. } => formatter
                .debug_struct("Denied")
                .field("redirect_to", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecisionError {
    #[error("authorization request is expired")]
    Expired,
    #[error("client is invalid")]
    InvalidClient,
    #[error("authorization request is invalid")]
    InvalidRequest,
    #[error("authorization request is not bound to this session")]
    SessionMismatch,
    #[error("authorization session is no longer valid")]
    SessionInactive,
    #[error("authorization storage is unavailable")]
    Storage,
    #[error("authorization quota exceeded")]
    QuotaExceeded,
}

pub async fn decide_authorization(
    state: &AppState,
    issuer: &IssuerSnapshot,
    request_id: &str,
    user_id: UserId,
    session_token: &str,
    decision: ConsentDecision,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<AuthorizationDecision, DecisionError> {
    let pending = match state.authorization_requests.find(request_id).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return Err(DecisionError::Expired),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to load OAuth authorization request");
            return Err(DecisionError::Storage);
        }
    };
    if pending.session_token_hash.as_deref() != Some(session_token_hash(session_token).as_str()) {
        return Err(DecisionError::SessionMismatch);
    }
    if matches!(decision, ConsentDecision::Deny) {
        return deny_authorization(state, request_id, user_id, pending, source_ip, user_agent)
            .await;
    }
    approve_authorization(
        state,
        issuer,
        request_id,
        user_id,
        session_token,
        pending,
        source_ip,
        user_agent,
    )
    .await
}

async fn deny_authorization(
    state: &AppState,
    request_id: &str,
    user_id: UserId,
    pending: PendingAuthorization,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<AuthorizationDecision, DecisionError> {
    // A pending request may outlive a Client update. Never return a denial
    // redirect to a URI that is no longer registered; approve already
    // revalidates the full authorization request, so deny must enforce the
    // same redirect trust boundary.
    let client = load_client(state, &pending.client_id).await?;
    if canonicalize_redirect_uri(&pending.redirect_uri).is_none_or(|redirect_uri| {
        !client
            .redirect_uris
            .iter()
            .any(|registered| redirect_uri_matches(registered, &redirect_uri))
    }) {
        return Err(DecisionError::InvalidRequest);
    }
    let consumed = consume_pending(state, request_id, &pending).await?;
    let pending = consumed.request;
    state
        .audit
        .record_best_effort(AuditEvent::new(
            "user".to_owned(),
            Some(user_id.to_string()),
            crate::audit::AuditAction::AuthorizationDenied,
            "oauth_authorization".to_owned(),
            Some(pending.client_id.clone()),
            crate::audit::with_request_context(
                serde_json::json!({"reason": "user_denied"}),
                source_ip,
                user_agent,
            ),
        ))
        .await;
    denial_redirect(&pending, &client)
        .map(|redirect_to| AuthorizationDecision::Denied { redirect_to })
        .ok_or(DecisionError::InvalidRequest)
}

async fn approve_authorization(
    state: &AppState,
    issuer: &IssuerSnapshot,
    request_id: &str,
    user_id: UserId,
    session_token: &str,
    pending: PendingAuthorization,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<AuthorizationDecision, DecisionError> {
    let validated = validated_pending(state, &pending).await?;
    let consumed = consume_pending(state, request_id, &pending).await?;
    if let Err(error_value) = session_still_active(state, session_token).await {
        restore_pending(state, &consumed.request, consumed.remaining_ttl_ms).await;
        return Err(error_value);
    }
    // `save` returns the new consent `state_version` (Issue #276). This path
    // deliberately ignores it: `issue_authorization_code_result` syncs the
    // cache fence from the database authority, so writing the version here
    // would add a second source for the same conditional-write conclusion.
    if let Err(error_value) =
        save_consent(state, user_id, &consumed.request, &validated.scopes).await
    {
        restore_pending(state, &consumed.request, consumed.remaining_ttl_ms).await;
        return Err(error_value);
    }
    match issue_authorization_code_result(
        state,
        issuer,
        user_id.to_string(),
        validated,
        source_ip,
        user_agent,
    )
    .await
    {
        Ok(AuthorizationCodeIssue::Redirect(redirect_to)) => {
            Ok(AuthorizationDecision::Approved { redirect_to })
        }
        Ok(AuthorizationCodeIssue::QuotaExceeded) => {
            restore_pending(state, &consumed.request, consumed.remaining_ttl_ms).await;
            Err(DecisionError::QuotaExceeded)
        }
        Err(_) => {
            restore_pending(state, &consumed.request, consumed.remaining_ttl_ms).await;
            Err(DecisionError::Storage)
        }
    }
}

async fn save_consent(
    state: &AppState,
    user_id: UserId,
    pending: &PendingAuthorization,
    scopes: &[String],
) -> Result<(), DecisionError> {
    match state
        .consents
        .save(user_id, &pending.client_id, scopes)
        .await
    {
        Ok(_) => Ok(()),
        Err(ConsentServiceError::ClientNotFound) => {
            tracing::error!(
                client_id = %pending.client_id,
                user_id = %user_id,
                "consent save rejected: OAuth client no longer exists"
            );
            Err(DecisionError::Storage)
        }
        Err(ConsentServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to save JSON OAuth consent");
            Err(DecisionError::Storage)
        }
    }
}

async fn consume_pending(
    state: &AppState,
    request_id: &str,
    pending: &PendingAuthorization,
) -> Result<ConsumedPendingAuthorization, DecisionError> {
    match state
        .authorization_requests
        .take_if_matches_with_ttl(request_id, pending)
        .await
    {
        Ok(Some(consumed)) => Ok(consumed),
        Ok(None) => Err(DecisionError::Expired),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to consume OAuth authorization request");
            Err(DecisionError::Storage)
        }
    }
}

async fn load_client(state: &AppState, client_id: &str) -> Result<RegisteredClient, DecisionError> {
    match state.clients.find_registered(client_id).await {
        Ok(Some(client)) => Ok(client),
        Ok(None) => Err(DecisionError::InvalidClient),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load OAuth client for consent");
            Err(DecisionError::Storage)
        }
    }
}

async fn validated_pending(
    state: &AppState,
    pending: &PendingAuthorization,
) -> Result<ValidatedAuthorizationRequest, DecisionError> {
    let client = load_client(state, &pending.client_id).await?;
    let mut validated = validate_authorization_request_with_allowlist(
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
        &state.config.client_registration_limits.allowed_scopes,
    )
    .map_err(|_| DecisionError::InvalidRequest)?;
    // The caller already verified the pending request is bound to the current
    // session. The authorization code must inherit that binding, otherwise a
    // logged-out user could still redeem the code within its TTL.
    validated.session_token_hash = pending.session_token_hash.clone();
    Ok(validated)
}

/// Re-check the session after the pending request is consumed.
///
/// The extractor only authenticates at request entry. Between consume and
/// code issue the session may have been revoked or the user disabled.
async fn session_still_active(state: &AppState, session_token: &str) -> Result<(), DecisionError> {
    let session = match state.sessions.find(session_token).await {
        Ok(Some(session)) if session.is_active_at(state.clock.now()) => session,
        Ok(_) => return Err(DecisionError::SessionInactive),
        Err(session_error) => {
            tracing::error!(error = %session_error, "OAuth session revalidation failed");
            return Err(DecisionError::Storage);
        }
    };
    match active_user_id(state, &session.user_id).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(DecisionError::SessionInactive),
        Err(user_error) => {
            tracing::error!(error = %user_error, "OAuth session revalidation failed");
            Err(DecisionError::Storage)
        }
    }
}

async fn restore_pending(state: &AppState, pending: &PendingAuthorization, remaining_ttl_ms: u64) {
    if remaining_ttl_ms == 0 {
        return;
    }
    if let Err(store_error) = state
        .authorization_requests
        .save_limited_with_ttl(pending, remaining_ttl_ms)
        .await
    {
        tracing::error!(error = %store_error, "failed to restore OAuth authorization request");
    }
}

pub(crate) fn denial_redirect(
    pending: &PendingAuthorization,
    client: &RegisteredClient,
) -> Option<String> {
    let redirect_uri = canonicalize_redirect_uri(&pending.redirect_uri)?;
    if !client
        .redirect_uris
        .iter()
        .any(|registered| redirect_uri_matches(registered, &redirect_uri))
    {
        return None;
    }
    let mut redirect = url::Url::parse(&redirect_uri).ok()?;
    redirect
        .query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("state", &pending.state);
    Some(redirect.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> RegisteredClient {
        RegisteredClient {
            client_id: "client-1".to_owned(),
            client_name: "Test Client".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            scopes: vec!["openid".to_owned()],
            owner_user_id: None,
        }
    }

    fn pending(redirect_uri: &str) -> PendingAuthorization {
        PendingAuthorization {
            request_id: "request-1".to_owned(),
            client_id: "client-1".to_owned(),
            redirect_uri: redirect_uri.to_owned(),
            scope: "openid".to_owned(),
            state: "state-1".to_owned(),
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: "S256".to_owned(),
            session_token_hash: Some("session-hash".to_owned()),
            holder_hash: Some("holder-hash".to_owned()),
            cas_revision: 0,
        }
    }

    #[test]
    fn denial_redirect_rejects_uri_removed_from_current_client_registration() {
        assert!(denial_redirect(&pending("https://retired.example/callback"), &client()).is_none());
    }

    #[test]
    fn denial_redirect_uses_canonical_current_registration_uri() {
        let redirect = denial_redirect(&pending("https://client.example:443/callback"), &client())
            .expect("currently registered redirect URI");
        assert!(redirect.starts_with("https://client.example/callback?"));
        assert!(redirect.contains("error=access_denied"));
        assert!(redirect.contains("state=state-1"));
    }
}
