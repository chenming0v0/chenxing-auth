use axum::{
    extract::{Path, State},
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

#[derive(Debug, Deserialize)]
pub struct CreateBindingBody {
    pub provider_id: Uuid,
    pub identifier: String,
    pub secret: String,
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<Uuid, Response> {
    let raw = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| error::bad_request("invalid_request", "Idempotency-Key is required"))?;
    Uuid::parse_str(raw)
        .map_err(|_| error::bad_request("invalid_request", "Idempotency-Key must be a UUID"))
}

pub async fn list_providers(State(state): State<AppState>, _session: SessionRead) -> Response {
    match state.account_portal.list_public_providers().await {
        Ok(items) => json_ok(items),
        Err(error) => service_error(error),
    }
}

pub async fn list_bindings(State(state): State<AppState>, session: SessionRead) -> Response {
    match state.account_portal.list_bindings(session.user_id).await {
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
        Err(response) => return response,
    };
    let Some(credential) = session.user_session_credential() else {
        return service_error(ServiceError::SessionInvalid);
    };
    match state
        .account_portal
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
    match state.account_portal.get_binding(session.user_id, id).await {
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
        Err(response) => return response,
    };
    let Some(credential) = session.user_session_credential() else {
        return service_error(ServiceError::SessionInvalid);
    };
    match state
        .account_portal
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
    match state.account_portal.sync_binding(session.user_id, id).await {
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
    match state.account_portal.unlink_binding(credential, id).await {
        Ok(()) => no_content(),
        Err(error) => service_error(error),
    }
}
