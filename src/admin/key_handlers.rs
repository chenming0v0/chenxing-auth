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

    let actor_type = actor.actor_type().to_owned();
    let actor_id = actor.user_id().map(|id| id.to_string());
    let request_id = uuid::Uuid::new_v4();
    if state
        .audit
        .record_blocking(key_change_event(
            actor_type.clone(),
            actor_id.clone(),
            crate::audit::AuditAction::SigningKeyRotate,
            request_id,
            "intent",
            None,
            serde_json::json!({"result": "pending"}),
        ))
        .await
        .is_err()
    {
        return error::internal();
    }

    let rotation = match state.keys.rotate().await {
        Ok(rotation) => rotation,
        Err(key_error) => {
            tracing::error!(error = %key_error, "failed to rotate signing key");
            record_key_outcome(
                &state,
                request_id,
                key_change_event(
                    actor_type,
                    actor_id,
                    crate::audit::AuditAction::SigningKeyRotate,
                    request_id,
                    "outcome",
                    None,
                    serde_json::json!({"result": "failure", "reason": "key_manager_error"}),
                ),
            )
            .await;
            return error::internal();
        }
    };
    let key_id = rotation.key_id;
    let published_key_count = rotation.published_key_count;
    record_key_outcome(
        &state,
        request_id,
        key_change_event(
            actor_type,
            actor_id,
            crate::audit::AuditAction::SigningKeyRotate,
            request_id,
            "outcome",
            Some(key_id.clone()),
            serde_json::json!({
                "result": "success",
                "published_key_count": published_key_count,
            }),
        ),
    )
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

    let actor_type = actor.actor_type().to_owned();
    let actor_id = actor.user_id().map(|id| id.to_string());
    let request_id = uuid::Uuid::new_v4();
    if state
        .audit
        .record_blocking(key_change_event(
            actor_type.clone(),
            actor_id.clone(),
            crate::audit::AuditAction::SigningKeyRevoke,
            request_id,
            "intent",
            Some(key_id.clone()),
            serde_json::json!({"result": "pending"}),
        ))
        .await
        .is_err()
    {
        return error::internal();
    }

    let revocation = match state.keys.revoke(&key_id).await {
        Ok(revocation) => revocation,
        Err(KeyManagerError::InvalidKeyId) => {
            record_key_failure(
                &state,
                actor_type,
                actor_id,
                request_id,
                key_id,
                "invalid_key_id",
            )
            .await;
            return error::bad_request("invalid_key_id", "key id is invalid");
        }
        Err(KeyManagerError::UnknownKeyId) => {
            record_key_failure(
                &state,
                actor_type,
                actor_id,
                request_id,
                key_id,
                "unknown_key_id",
            )
            .await;
            return error::not_found("signing_key_not_found", "signing key was not found");
        }
        Err(KeyManagerError::NoActiveKeyReplacement) => {
            record_key_failure(
                &state,
                actor_type,
                actor_id,
                request_id,
                key_id,
                "no_active_key_replacement",
            )
            .await;
            return error::conflict(
                "active_signing_key_required",
                "cannot revoke the active signing key without another valid signing key",
            );
        }
        Err(key_error) => {
            tracing::error!(key_id = %key_id, error = %key_error, "failed to revoke signing key");
            record_key_failure(
                &state,
                actor_type,
                actor_id,
                request_id,
                key_id,
                "key_manager_error",
            )
            .await;
            return error::internal();
        }
    };

    let key_id = revocation.key_id.clone();
    let active_key_id = revocation.active_key_id.clone();
    let published_key_count = revocation.published_key_count;
    record_key_outcome(
        &state,
        request_id,
        key_change_event(
            actor_type,
            actor_id,
            crate::audit::AuditAction::SigningKeyRevoke,
            request_id,
            "outcome",
            Some(key_id.clone()),
            serde_json::json!({
                "result": "success",
                "active_key_id": active_key_id.clone(),
                "published_key_count": published_key_count,
            }),
        ),
    )
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

async fn record_key_failure(
    state: &AppState,
    actor_type: String,
    actor_id: Option<String>,
    request_id: uuid::Uuid,
    key_id: String,
    reason: &'static str,
) {
    record_key_outcome(
        state,
        request_id,
        key_change_event(
            actor_type,
            actor_id,
            crate::audit::AuditAction::SigningKeyRevoke,
            request_id,
            "outcome",
            Some(key_id),
            serde_json::json!({"result": "failure", "reason": reason}),
        ),
    )
    .await;
}

async fn record_key_outcome(state: &AppState, request_id: uuid::Uuid, event: AuditEvent) {
    if state.audit.record_blocking(event).await.is_err() {
        tracing::error!(
            event = "signing_key.audit_outcome_pending",
            request_id = %request_id,
            "signing key outcome could not be persisted; durable intent remains pending"
        );
    }
}

fn key_change_event(
    actor_type: String,
    actor_id: Option<String>,
    action: crate::audit::AuditAction,
    request_id: uuid::Uuid,
    phase: &'static str,
    resource_id: Option<String>,
    metadata: serde_json::Value,
) -> AuditEvent {
    let mut metadata = match metadata {
        serde_json::Value::Object(metadata) => metadata,
        _ => serde_json::Map::new(),
    };
    metadata.insert(
        "request_id".to_owned(),
        serde_json::Value::String(request_id.to_string()),
    );
    metadata.insert(
        "phase".to_owned(),
        serde_json::Value::String(phase.to_owned()),
    );
    AuditEvent::new(
        actor_type,
        actor_id,
        action,
        "signing_key".to_owned(),
        resource_id,
        serde_json::Value::Object(metadata),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_change_events_keep_request_and_phase_correlation() {
        let request_id = uuid::Uuid::nil();
        let event = key_change_event(
            "system".to_owned(),
            None,
            crate::audit::AuditAction::SigningKeyRotate,
            request_id,
            "intent",
            None,
            serde_json::json!({"requested": true}),
        );

        assert_eq!(event.metadata["request_id"], request_id.to_string());
        assert_eq!(event.metadata["phase"], "intent");
        assert_eq!(event.metadata["requested"], true);
    }
}
