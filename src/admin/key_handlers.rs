use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use super::domain::AdminPermission;
use crate::{
    api::extract::AdminWrite, audit::AuditEvent, error, keys::KeyManagerError, state::AppState,
};

#[derive(Debug, Serialize)]
pub struct KeyRotationResponse {
    pub key_id: String,
    pub published_key_count: usize,
}

#[derive(Debug, Serialize)]
pub struct KeyRevocationResponse {
    pub key_id: String,
    pub active_key_id: String,
    pub published_key_count: usize,
}

pub async fn rotate_signing_key(State(state): State<AppState>, admin: AdminWrite) -> Response {
    let actor = match admin.authorize(&state, AdminPermission::RotateKeys).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };

    let rotation = match state.keys.rotate().await {
        Ok(rotation) => rotation,
        Err(key_error) => {
            tracing::error!(error = %key_error, "failed to rotate signing key");
            return error::internal();
        }
    };
    let key_id = rotation.key_id;
    let published_key_count = rotation.published_key_count;
    // Rotation has already changed the shared in-memory state and key files. It is
    // deliberately not compensated on an audit outage: returning 500 would invite
    // a second, non-idempotent rotation. `record_best_effort` emits the alert context.
    state
        .audit
        .record_best_effort(AuditEvent::new(
            actor.actor_type().to_owned(),
            actor.user_id().map(|id| id.to_string()),
            crate::audit::AuditAction::SigningKeyRotate,
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

pub async fn revoke_signing_key(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(key_id): Path<String>,
) -> Response {
    let actor = match admin.authorize(&state, AdminPermission::RotateKeys).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };

    let revocation = match state.keys.revoke(&key_id).await {
        Ok(revocation) => revocation,
        Err(KeyManagerError::InvalidKeyId) => {
            return error::bad_request("invalid_key_id", "key id is invalid");
        }
        Err(KeyManagerError::UnknownKeyId) => {
            return error::not_found("signing_key_not_found", "signing key was not found");
        }
        Err(KeyManagerError::NoActiveKeyReplacement) => {
            return error::conflict(
                "active_signing_key_required",
                "cannot revoke the active signing key without another valid signing key",
            );
        }
        Err(key_error) => {
            tracing::error!(key_id = %key_id, error = %key_error, "failed to revoke signing key");
            return error::internal();
        }
    };

    let key_id = revocation.key_id.clone();
    let active_key_id = revocation.active_key_id.clone();
    let published_key_count = revocation.published_key_count;
    // Revocation is also authoritative before audit persistence; the response must
    // describe the effective key state rather than a later audit outage.
    state
        .audit
        .record_best_effort(AuditEvent::new(
            actor.actor_type().to_owned(),
            actor.user_id().map(|id| id.to_string()),
            crate::audit::AuditAction::SigningKeyRevoke,
            "signing_key".to_owned(),
            Some(key_id.clone()),
            serde_json::json!({
                "active_key_id": active_key_id.clone(),
                "published_key_count": published_key_count,
            }),
        ))
        .await;

    (
        StatusCode::OK,
        Json(KeyRevocationResponse {
            key_id,
            active_key_id,
            published_key_count,
        }),
    )
        .into_response()
}
