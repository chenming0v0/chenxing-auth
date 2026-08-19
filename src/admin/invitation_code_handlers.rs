use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use super::domain::AdminPermission;
use crate::{
    api::extract::{AdminRead, AdminWrite, ApiJson},
    error,
    invitation_codes::{self, CreateInvitationCodesInput, InvitationCodeError},
    state::AppState,
};

pub async fn list_invitation_codes(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        return response;
    }
    match invitation_codes::list(&state.database).await {
        Ok(codes) => (StatusCode::OK, Json(codes)).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list registration invitation codes");
            error::internal()
        }
    }
}

pub async fn create_invitation_codes(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(input): ApiJson<CreateInvitationCodesInput>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match invitation_codes::create_batch(&state.database, input, actor.user_id()).await {
        Ok(codes) => {
            let (actor_type, actor_id) = actor.audit_fields();
            state
                .audit
                .record_best_effort(crate::audit::AuditEvent::new(
                    actor_type.to_owned(), actor_id,
                    crate::audit::AuditAction::InvitationCodeCreate,
                    "registration_invitation_code".to_owned(), None,
                    serde_json::json!({"count": codes.len(), "ids": codes.iter().map(|code| code.summary.id).collect::<Vec<_>>() }),
                ))
                .await;
            (StatusCode::CREATED, Json(codes)).into_response()
        }
        Err(InvitationCodeError::InvalidInput) => error::bad_request(
            "invalid_invitation_code_request",
            "invitation code request is invalid",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create registration invitation codes");
            error::internal()
        }
    }
}

pub async fn disable_invitation_code(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(id): Path<i64>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match invitation_codes::disable(&state.database, id).await {
        Ok(code) => {
            let (actor_type, actor_id) = actor.audit_fields();
            state
                .audit
                .record_best_effort(crate::audit::AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id,
                    crate::audit::AuditAction::InvitationCodeDisable,
                    "registration_invitation_code".to_owned(),
                    Some(id.to_string()),
                    serde_json::json!({}),
                ))
                .await;
            (StatusCode::OK, Json(code)).into_response()
        }
        Err(InvitationCodeError::NotFound) => {
            error::not_found("invitation_code_not_found", "invitation code was not found")
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to disable registration invitation code");
            error::internal()
        }
    }
}
