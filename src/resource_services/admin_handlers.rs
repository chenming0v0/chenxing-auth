use axum::{
    extract::{Path, State},
    response::Response,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    admin::{authorization::authorize_admin_write, domain::AdminPermission},
    api::extract::{AdminRead, AdminWrite, ApiJson},
    audit::{AuditAction, AuditEvent},
    state::AppState,
};

use super::response::{json_created, json_ok, service_error};
use super::service::ProviderWrite;
use super::service_error::ServiceError;
use super::types::ScopeAccess;

#[derive(Debug, Deserialize)]
pub struct ProviderBody {
    pub slug: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// 缺省为 `<slug>:access`。
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub scope_description: String,
    #[serde(default)]
    pub scope_access: ScopeAccess,
    #[serde(default)]
    pub allowed_client_ids: Vec<String>,
    pub expected_revision: i64,
}

impl ProviderBody {
    fn into_write(self) -> ProviderWrite {
        ProviderWrite {
            slug: self.slug,
            display_name: self.display_name,
            issuer: self.issuer,
            client_id: self.client_id,
            client_secret: self.client_secret,
            scope: self.scope,
            scope_description: self.scope_description,
            scope_access: self.scope_access,
            allowed_client_ids: self.allowed_client_ids,
            expected_revision: self.expected_revision,
        }
    }
}

pub async fn list(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageIdentityProviders)
        .await
    {
        return response;
    }
    match state.resource_services.list_admin_providers().await {
        Ok(items) => json_ok(items),
        Err(error) => service_error(error),
    }
}

pub async fn get(
    State(state): State<AppState>,
    admin: AdminRead,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageIdentityProviders)
        .await
    {
        return response;
    }
    match state.resource_services.get_admin_provider(id).await {
        Ok(Some(item)) => json_ok(item),
        Ok(None) => service_error(ServiceError::ProviderNotFound),
        Err(error) => service_error(error),
    }
}

pub async fn create(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(body): ApiJson<ProviderBody>,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageIdentityProviders).await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    let (actor_type, actor_id) = authorization.actor().audit_fields();
    let event = AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        AuditAction::ResourceServiceProviderSave,
        "resource_service_provider".to_owned(),
        None,
        serde_json::json!({ "issuer": body.issuer, "slug": body.slug }),
    );
    match state
        .resource_services
        .create_provider(
            body.into_write(),
            &state.audit,
            authorization.credential(),
            event,
        )
        .await
    {
        Ok(item) => json_created(item),
        Err(error) => service_error(error),
    }
}

pub async fn update(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ProviderBody>,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageIdentityProviders).await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    let (actor_type, actor_id) = authorization.actor().audit_fields();
    let event = AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        AuditAction::ResourceServiceProviderSave,
        "resource_service_provider".to_owned(),
        Some(id.to_string()),
        serde_json::json!({ "revision": body.expected_revision, "slug": body.slug }),
    );
    match state
        .resource_services
        .update_provider(
            id,
            body.into_write(),
            &state.audit,
            authorization.credential(),
            event,
        )
        .await
    {
        Ok(item) => json_ok(item),
        Err(error) => service_error(error),
    }
}

pub async fn set_enabled(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(id): Path<Uuid>,
    enabled: bool,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageIdentityProviders).await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    let (actor_type, actor_id) = authorization.actor().audit_fields();
    let action = if enabled {
        AuditAction::ResourceServiceProviderSave
    } else {
        AuditAction::ResourceServiceProviderDisable
    };
    let event = AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        action,
        "resource_service_provider".to_owned(),
        Some(id.to_string()),
        serde_json::json!({ "enabled": enabled }),
    );
    match state
        .resource_services
        .set_provider_enabled(id, enabled, &state.audit, authorization.credential(), event)
        .await
    {
        Ok(item) => json_ok(item),
        Err(error) => service_error(error),
    }
}

pub async fn enable(state: State<AppState>, admin: AdminWrite, path: Path<Uuid>) -> Response {
    set_enabled(state, admin, path, true).await
}

pub async fn disable(state: State<AppState>, admin: AdminWrite, path: Path<Uuid>) -> Response {
    set_enabled(state, admin, path, false).await
}
