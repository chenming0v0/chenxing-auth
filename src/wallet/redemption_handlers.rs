use super::{
    redemption_domain::{CreateRedemptionCodesInput, RedeemCodeInput},
    redemption_service::RedemptionError,
};
use crate::admin::{
    authorization::{authorize_admin_write, management_actor_validation_failed},
    domain::AdminPermission,
};
use crate::{
    api::extract::{AdminRead, AdminWrite, ApiJson, SessionWrite},
    audit::AuditEvent,
    error,
    state::AppState,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub async fn list_redemption_codes(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        return response;
    }
    match state.redemptions.list().await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list wallet redemption codes");
            error::internal()
        }
    }
}

pub async fn get_redemption_code(
    State(state): State<AppState>,
    admin: AdminRead,
    Path(id): Path<i64>,
) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        return response;
    }
    match state.redemptions.detail(id).await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(RedemptionError::NotFound) => {
            error::not_found("redemption_code_not_found", "redemption code was not found")
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load wallet redemption code");
            error::internal()
        }
    }
}

pub async fn create_redemption_codes(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(input): ApiJson<CreateRedemptionCodesInput>,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageSettings).await {
            Ok(value) => value,
            Err(response) => return response,
        };
    let actor = authorization.actor();
    match state.redemptions.create_batch(input, actor.user_id(), authorization.credential(), move |codes| {
        let (actor_type, actor_id) = actor.audit_fields();
        AuditEvent::new(actor_type.to_owned(), actor_id, crate::audit::AuditAction::WalletRedemptionCodeCreate, "wallet_redemption_code".to_owned(), None, serde_json::json!({"count": codes.len(), "ids": codes.iter().map(|code| code.summary.id).collect::<Vec<_>>() }))
    }).await {
        Ok(value) => (StatusCode::CREATED, Json(value)).into_response(), Err(RedemptionError::InvalidInput) => error::bad_request("invalid_redemption_code_request", "redemption code request is invalid"), Err(RedemptionError::ManagementActor(value)) => management_actor_validation_failed(&state, authorization, value).await, Err(value) => { tracing::error!(error = %value, "failed to create wallet redemption codes"); error::internal() }
    }
}

pub async fn disable_redemption_code(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(id): Path<i64>,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageSettings).await {
            Ok(value) => value,
            Err(response) => return response,
        };
    let actor = authorization.actor();
    let (actor_type, actor_id) = actor.audit_fields();
    let audit = AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        crate::audit::AuditAction::WalletRedemptionCodeDisable,
        "wallet_redemption_code".to_owned(),
        Some(id.to_string()),
        serde_json::json!({}),
    );
    match state
        .redemptions
        .disable(id, authorization.credential(), audit)
        .await
    {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(RedemptionError::NotFound) => {
            error::not_found("redemption_code_not_found", "redemption code was not found")
        }
        Err(RedemptionError::ManagementActor(value)) => {
            management_actor_validation_failed(&state, authorization, value).await
        }
        Err(value) => {
            tracing::error!(error = %value, "failed to disable wallet redemption code");
            error::internal()
        }
    }
}

pub async fn redeem_wallet_code(
    State(state): State<AppState>,
    session: SessionWrite,
    ApiJson(input): ApiJson<RedeemCodeInput>,
) -> Response {
    let audit = AuditEvent::new(
        "user".to_owned(),
        Some(session.user_id.to_string()),
        crate::audit::AuditAction::WalletRedemption,
        "wallet_redemption_code".to_owned(),
        None,
        serde_json::json!({"result":"success"}),
    );
    match state
        .redemptions
        .redeem(session.user_id, &input.code, audit)
        .await
    {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(RedemptionError::InvalidCode) => {
            error::bad_request("invalid_redemption_code", "redemption code is invalid")
        }
        Err(value) => {
            tracing::error!(error = %value, "wallet redemption failed");
            error::internal()
        }
    }
}
