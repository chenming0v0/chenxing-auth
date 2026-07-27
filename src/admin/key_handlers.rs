use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::{audit::AuditEvent, error, state::AppState};

#[derive(Debug, Serialize)]
pub struct KeyRotationResponse {
    pub key_id: String,
    pub published_key_count: usize,
}

pub async fn rotate_signing_key(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !super::handlers::is_admin_request(&state, &headers) {
        return error::unauthorized("admin_required", "administrator authorization is required");
    }

    if let Err(key_error) = state.keys.rotate() {
        tracing::error!(error = %key_error, "failed to rotate signing key");
        return error::internal();
    }
    let key_id = state.keys.key_id();
    let published_key_count = state.keys.jwks().keys.len();
    state
        .audit
        .record(AuditEvent::new(
            "admin".to_owned(),
            None,
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
