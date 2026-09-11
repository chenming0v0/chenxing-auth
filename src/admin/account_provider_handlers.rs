use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{
    admin::{
        authorization::{authorize_admin_write, management_actor_validation_failed},
        domain::AdminPermission,
    },
    api::extract::{AdminRead, AdminWrite, ApiJson},
    audit::{AuditAction, AuditEvent},
    error,
    oauth::response::with_no_store_headers,
    settings::account_providers::{AccountProviderError, AccountProviderInput},
    state::AppState,
};

pub async fn list(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageIdentityProviders)
        .await
    {
        return response;
    }
    match state.settings.account_providers().await {
        Ok(items) => with_no_store_headers(Json(items).into_response()),
        Err(_) => unavailable(),
    }
}

pub async fn save(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(slug): Path<String>,
    ApiJson(input): ApiJson<AccountProviderInput>,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageIdentityProviders).await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    if input.slug != slug {
        return error::bad_request(
            "invalid_account_provider",
            "provider slug cannot be changed",
        );
    }
    let creating = input.expected_version == 0;
    let (actor_type, actor_id) = authorization.actor().audit_fields();
    let event = AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        AuditAction::AccountProviderSave,
        "account_provider".to_owned(),
        Some(slug),
        serde_json::json!({
            "enabled": input.enabled,
            "client_count": input.allowed_client_ids.len(),
            "outbound_rotated": input.outbound_token.is_some(),
            "inbound_rotated": input.inbound_token.is_some(),
        }),
    );
    let result = state
        .settings
        .save_account_provider(input, &state.audit, authorization.credential(), event)
        .await;
    let response = match result {
        Ok(provider) => (
            if creating {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            Json(provider),
        )
            .into_response(),
        Err(AccountProviderError::ManagementActor(value)) => {
            management_actor_validation_failed(&state, authorization, value).await
        }
        Err(AccountProviderError::Invalid(field)) => error::bad_request(
            "invalid_account_provider",
            format!("invalid account provider field: {field}"),
        ),
        Err(AccountProviderError::Conflict) => error::conflict(
            "account_provider_conflict",
            "provider changed; reload and retry",
        ),
        Err(AccountProviderError::ClientConflict) => error::conflict(
            "account_provider_client_conflict",
            "client ID belongs to another provider",
        ),
        Err(_) => unavailable(),
    };
    with_no_store_headers(response)
}

fn unavailable() -> Response {
    with_no_store_headers(error::service_unavailable(
        "provider_unavailable",
        "provider settings are temporarily unavailable",
    ))
}
