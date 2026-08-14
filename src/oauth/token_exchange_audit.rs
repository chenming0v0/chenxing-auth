use super::{OAuthError, TokenResponse};
use crate::{
    oauth::token_security::{
        record_token_event_with_metadata, record_token_event_with_metadata_best_effort,
    },
    state::AppState,
};

pub(super) async fn exchange_failure(
    state: &AppState,
    user_id: Option<&str>,
    client_id: Option<&str>,
    reason: &'static str,
    error: OAuthError,
) -> Result<TokenResponse, OAuthError> {
    record_token_exchange_failure(state, user_id, client_id, reason).await;
    Err(error)
}

pub(super) async fn record_token_exchange_success(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    scopes: &[String],
) -> Result<(), crate::audit::AuditError> {
    record_token_event_with_metadata(
        state,
        Some(user_id),
        crate::audit::AuditAction::TokenExchange,
        Some(client_id),
        serde_json::json!({
            "client_id": client_id,
            "user_id": user_id,
            "scopes": scopes,
            "result": "success",
        }),
    )
    .await
}

async fn record_token_exchange_failure(
    state: &AppState,
    user_id: Option<&str>,
    client_id: Option<&str>,
    reason: &'static str,
) {
    record_token_event_with_metadata_best_effort(
        state,
        user_id,
        crate::audit::AuditAction::TokenExchangeFailure,
        client_id,
        serde_json::json!({
            "client_id": client_id,
            "user_id": user_id,
            "reason": reason,
            "result": "failure",
        }),
    )
    .await;
}
