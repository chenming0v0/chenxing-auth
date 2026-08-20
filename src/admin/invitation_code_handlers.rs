use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use super::{
    authorization::{authorize_admin_write, management_actor_validation_failed},
    domain::AdminPermission,
};
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
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageSettings).await {
            Ok(authorization) => authorization,
            Err(response) => return response,
        };
    let actor = authorization.actor();
    match invitation_codes::create_batch_with_audit(
        &state.database,
        input,
        actor.user_id(),
        authorization.credential(),
        move |codes| {
            let (actor_type, actor_id) = actor.audit_fields();
            crate::audit::AuditEvent::new(
                actor_type.to_owned(),
                actor_id,
                crate::audit::AuditAction::InvitationCodeCreate,
                "registration_invitation_code".to_owned(),
                None,
                serde_json::json!({
                    "count": codes.len(),
                    "ids": codes.iter().map(|code| code.summary.id).collect::<Vec<_>>()
                }),
            )
        },
    )
    .await
    {
        Ok(codes) => (StatusCode::CREATED, Json(codes)).into_response(),
        Err(InvitationCodeError::InvalidInput) => error::bad_request(
            "invalid_invitation_code_request",
            "invitation code request is invalid",
        ),
        Err(InvitationCodeError::ManagementActor(error_value)) => {
            management_actor_validation_failed(&state, authorization, error_value).await
        }
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
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageSettings).await {
            Ok(authorization) => authorization,
            Err(response) => return response,
        };
    let actor = authorization.actor();
    let (actor_type, actor_id) = actor.audit_fields();
    let event = crate::audit::AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        crate::audit::AuditAction::InvitationCodeDisable,
        "registration_invitation_code".to_owned(),
        Some(id.to_string()),
        serde_json::json!({}),
    );
    match invitation_codes::disable_with_audit(
        &state.database,
        id,
        authorization.credential(),
        event,
    )
    .await
    {
        Ok(code) => (StatusCode::OK, Json(code)).into_response(),
        Err(InvitationCodeError::NotFound) => {
            error::not_found("invitation_code_not_found", "invitation code was not found")
        }
        Err(InvitationCodeError::ManagementActor(error_value)) => {
            management_actor_validation_failed(&state, authorization, error_value).await
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to disable registration invitation code");
            error::internal()
        }
    }
}
