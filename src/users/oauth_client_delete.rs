use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{
    api::extract::SessionWrite, audit::AuditEvent, clients::service::ClientServiceError, error,
    state::AppState,
};

pub async fn delete_owned_client(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(client_id): Path<String>,
) -> Response {
    let actor_id = session.user_id.to_string();
    match state
        .clients
        .delete_for_user_with_audit(
            session.user_id,
            &client_id,
            AuditEvent::new(
                "user".to_owned(),
                Some(actor_id),
                crate::audit::AuditAction::ClientDelete,
                "oauth_client".to_owned(),
                Some(client_id.clone()),
                serde_json::json!({"result": "success"}),
            ),
        )
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error::not_found("oauth_client_not_found", "OAuth project was not found"),
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to delete owned OAuth client");
            error::internal()
        }
        Err(ClientServiceError::AuditUnavailable) => error::service_unavailable(
            "audit_unavailable",
            "the operation was rolled back because its audit record could not be written; retry later",
        ),
        Err(
            ClientServiceError::Validation(_)
            | ClientServiceError::SecretHash
            | ClientServiceError::InvalidData
            | ClientServiceError::QuotaExceeded
            | ClientServiceError::SecretRotationConflict
            | ClientServiceError::AndroidLink(_)
            | ClientServiceError::IdempotencyKeyInvalid
            | ClientServiceError::IdempotencyConflict
            | ClientServiceError::IdempotencyKeyUnavailable
            | ClientServiceError::IdempotencyCorruptResult,
        ) => error::internal(),
    }
}
