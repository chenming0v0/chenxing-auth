use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use super::authorization::{
    authorize_user_write, management_actor_permission_denied, management_actor_session_invalid,
};
use crate::{
    api::extract::{AdminWrite, ApiJson},
    audit::AuditEvent,
    state::AppState,
    users::domain::UserId,
    wallet::{domain::CreditInput, handlers::wallet_error_response, service::WalletServiceError},
};

/// `POST /api/v1/admin/users/{user_id}/wallet/credit`
///
/// Credits 辰星点 onto a user's lazy wallet. Permission matches plan
/// assignment: `ManageUsers` plus AdminWrite CSRF.
pub async fn credit_user_wallet(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(user_id): Path<UserId>,
    ApiJson(input): ApiJson<CreditInput>,
) -> Response {
    let authorization = match authorize_user_write(&state, &admin).await {
        Ok(authorization) => authorization,
        Err(response) => return response,
    };
    let actor = authorization.actor();
    let event = AuditEvent::new(
        actor.actor_type().to_owned(),
        actor.user_id().map(|id| id.to_string()),
        crate::audit::AuditAction::WalletCredit,
        "user".to_owned(),
        Some(user_id.to_string()),
        serde_json::json!({"result": "success"}),
    );
    match state
        .wallets
        .credit(user_id, input, authorization.credential(), event)
        .await
    {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(WalletServiceError::ActorSessionInvalid) => {
            management_actor_session_invalid(&state, authorization).await
        }
        Err(WalletServiceError::ActorPermissionRequired) => {
            management_actor_permission_denied(&state, authorization).await
        }
        Err(error_value) => wallet_error_response(error_value),
    }
}
