use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    api::extract::{ApiJson, SessionRead, SessionWrite},
    error,
    state::AppState,
};

use super::response::{json_created, json_ok, no_content, service_error};
use super::service_error::ServiceError;

#[derive(Debug, Default, Deserialize)]
pub struct ScopeQuery {
    /// 编辑既有应用时传入；缺省表示新应用，只能看到 public 资源服务 scope。
    #[serde(default)]
    pub client_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateBindingBody {
    pub provider_id: Uuid,
    pub identifier: String,
    pub secret: String,
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<Uuid, &'static str> {
    let raw = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or("Idempotency-Key is required")?;
    Uuid::parse_str(raw).map_err(|_| "Idempotency-Key must be a UUID")
}

fn missing_idempotency_key(message: &'static str) -> Response {
    error::bad_request("invalid_request", message)
}

pub async fn list_providers(State(state): State<AppState>, _session: SessionRead) -> Response {
    match state.resource_services.list_public_providers().await {
        Ok(items) => json_ok(items),
        Err(error) => service_error(error),
    }
}

/// `GET /api/v1/auth/oauth-scopes?client_id=`：应用注册抽屉的权限目录。
pub async fn scope_catalog(
    State(state): State<AppState>,
    _session: SessionRead,
    Query(query): Query<ScopeQuery>,
) -> Response {
    let client_id = query
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let base = &state.config.client_registration_limits.allowed_scopes;
    match state.resource_services.scope_catalog(base, client_id).await {
        Ok(items) => json_ok(serde_json::json!({ "items": items })),
        Err(_) => service_error(ServiceError::Unavailable),
    }
}

pub async fn list_bindings(State(state): State<AppState>, session: SessionRead) -> Response {
    match state.resource_services.list_bindings(session.user_id).await {
        Ok(items) => json_ok(items),
        Err(error) => service_error(error),
    }
}

pub async fn create_binding(
    State(state): State<AppState>,
    session: SessionWrite,
    headers: HeaderMap,
    ApiJson(body): ApiJson<CreateBindingBody>,
) -> Response {
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(message) => return missing_idempotency_key(message),
    };
    let Some(credential) = session.user_session_credential() else {
        return service_error(ServiceError::SessionInvalid);
    };
    match state
        .resource_services
        .create_binding(
            credential,
            body.provider_id,
            idempotency_key,
            body.identifier,
            body.secret,
        )
        .await
    {
        Ok(item) => json_created(item),
        Err(error) => service_error(error),
    }
}

pub async fn get_binding(
    State(state): State<AppState>,
    session: SessionRead,
    Path(id): Path<Uuid>,
) -> Response {
    match state
        .resource_services
        .get_binding(session.user_id, id)
        .await
    {
        Ok(item) => json_ok(item),
        Err(error) => service_error(error),
    }
}

pub async fn refresh_binding(
    State(state): State<AppState>,
    session: SessionWrite,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(message) => return missing_idempotency_key(message),
    };
    let Some(credential) = session.user_session_credential() else {
        return service_error(ServiceError::SessionInvalid);
    };
    match state
        .resource_services
        .refresh_binding(credential, id, idempotency_key)
        .await
    {
        Ok(item) => json_ok(item),
        Err(error) => service_error(error),
    }
}

pub async fn sync_binding(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(id): Path<Uuid>,
) -> Response {
    let Some(credential) = session.user_session_credential() else {
        return service_error(ServiceError::SessionInvalid);
    };
    match state.resource_services.sync_binding(credential, id).await {
        Ok(item) => json_ok(item),
        Err(error) => service_error(error),
    }
}

pub async fn unlink_binding(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(id): Path<Uuid>,
) -> Response {
    let Some(credential) = session.user_session_credential() else {
        return service_error(ServiceError::SessionInvalid);
    };
    match state.resource_services.unlink_binding(credential, id).await {
        Ok(()) => no_content(),
        Err(error) => service_error(error),
    }
}
