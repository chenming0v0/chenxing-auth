use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use super::{authorization::current_admin_mutation, domain::AdminPermission};
use crate::{audit::AuditEvent, error, state::AppState};

#[derive(Debug, Serialize)]
pub struct KeyRotationResponse {
    pub key_id: String,
    pub published_key_count: usize,
}

pub async fn rotate_signing_key(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let actor = match current_admin_mutation(&state, &headers, AdminPermission::RotateKeys).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };

    if let Err(key_error) = state.keys.rotate() {
        tracing::error!(error = %key_error, "failed to rotate signing key");
        return error::internal();
    }
    let key_id = state.keys.key_id();
    let published_key_count = state.keys.jwks().keys.len();
    state
        .audit
        .record(AuditEvent::new(
            actor.actor_type().to_owned(),
            actor.user_id().map(|id| id.to_string()),
            "signing_key_rotate".to_owned(),
            "signing_key".to_owned(),
            Some(key_id.clone()),
            serde_json::json!({"published_key_count": published_key_count}),
        ))
        .await;

    (
        StatusCode::OK,
        Json(KeyRotationResponse {
            key_id,
            published_key_count,
        }),
    )
        .into_response()
}
