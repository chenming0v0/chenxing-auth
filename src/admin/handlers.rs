use axum::{
    Json,
    extract::Path,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::{
    admin::{
        authorization::{current_admin_mutation, current_admin_permission},
        domain::AdminPermission,
    },
    audit::AuditEvent,
    clients::{domain::ClientRegistrationInput, service::ClientServiceError},
    error,
    state::AppState,
};

#[derive(Debug, Serialize)]
struct RegisteredClientResponse {
    id: uuid::Uuid,
    client_id: String,
    client_secret: String,
    client_name: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ClientSummary {
    id: uuid::Uuid,
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    status: String,
    owner_user_id: Option<uuid::Uuid>,
}

pub async fn create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ClientRegistrationInput>,
) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageClients).await
    {
        return response;
    }

    match state.clients.register(input).await {
        Ok(client) => {
            let client_id = client.client_id.clone();
            let response = (
                axum::http::StatusCode::CREATED,
                Json(RegisteredClientResponse {
                    id: client.id,
                    client_id: client.client_id,
                    client_secret: client.client_secret,
                    client_name: client.client_name,
                    redirect_uris: client.redirect_uris,
                    scopes: client.scopes,
                }),
            )
                .into_response();
            record_admin_event(&state, "client_create", &client_id).await;
            response
        }
        Err(ClientServiceError::Validation(validation_error)) => {
            error::bad_request("invalid_client_registration", validation_error.to_string())
        }
        Err(ClientServiceError::Database(database_error)) => {
            if database_error
                .as_database_error()
                .and_then(|database_error| database_error.code())
                .is_some_and(|code| code == "23505")
            {
                error::conflict(
                    "client_id_conflict",
                    "client registration conflicts with existing data",
                )
            } else {
                tracing::error!(error = %database_error, "failed to create OAuth client");
                error::internal()
            }
        }
        Err(
            ClientServiceError::SecretHash
            | ClientServiceError::InvalidData
            | ClientServiceError::QuotaExceeded,
        ) => {
            tracing::error!("failed to create OAuth client secret");
            error::internal()
        }
    }
}

pub async fn list_clients(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_mutation(&state, &headers, AdminPermission::ManageClients).await
    {
        return response;
    }
    match state.clients.list().await {
        Ok(clients) => (
            axum::http::StatusCode::OK,
            Json(
                clients
                    .into_iter()
                    .map(|client| ClientSummary {
                        id: client.id,
                        client_id: client.client_id,
                        client_name: client.client_name,
                        redirect_uris: client.redirect_uris,
                        scopes: client.scopes,
                        status: client.status,
                        owner_user_id: client.owner_user_id,
                    })
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to list OAuth clients");
            error::internal()
        }
    }
}

pub async fn update_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(input): Json<ClientRegistrationInput>,
) -> Response {
    if let Err(response) =
        current_admin_mutation(&state, &headers, AdminPermission::ManageClients).await
    {
        return response;
    }
    match state.clients.update(&client_id, input).await {
        Ok(true) => {
            state
                .audit
                .record(AuditEvent::new(
                    "admin".to_owned(),
                    None,
                    "client_update".to_owned(),
                    "oauth_client".to_owned(),
                    Some(client_id.clone()),
                    serde_json::json!({"result": "success"}),
                ))
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::bad_request("client_not_found", "client was not found"),
        Err(ClientServiceError::Validation(validation_error)) => {
            error::bad_request("invalid_client_registration", validation_error.to_string())
        }
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to update OAuth client");
            error::internal()
        }
        Err(
            ClientServiceError::SecretHash
            | ClientServiceError::InvalidData
            | ClientServiceError::QuotaExceeded,
        ) => error::internal(),
    }
}

pub async fn set_client_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    status: &'static str,
) -> Response {
    if let Err(response) =
        current_admin_mutation(&state, &headers, AdminPermission::ManageClients).await
    {
        return response;
    }
    match state.clients.set_status(&client_id, status).await {
        Ok(true) => {
            state
                .audit
                .record(AuditEvent::new(
                    "admin".to_owned(),
                    None,
                    format!("client_{status}"),
                    "oauth_client".to_owned(),
                    Some(client_id.clone()),
                    serde_json::json!({"result": "success"}),
                ))
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::bad_request("client_not_found", "client was not found"),
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to update OAuth client status");
            error::internal()
        }
        Err(ClientServiceError::InvalidData) => {
            error::bad_request("invalid_status", "status is invalid")
        }
        Err(ClientServiceError::Validation(_))
        | Err(ClientServiceError::SecretHash)
        | Err(ClientServiceError::QuotaExceeded) => error::internal(),
    }
}

pub async fn disable_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Response {
    set_client_status(State(state), headers, Path(client_id), "disabled").await
}

pub async fn enable_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Response {
    set_client_status(State(state), headers, Path(client_id), "active").await
}

pub async fn rotate_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Response {
    if let Err(response) =
        current_admin_mutation(&state, &headers, AdminPermission::ManageClients).await
    {
        return response;
    }
    match state.clients.rotate_secret(&client_id).await {
        Ok(secret) => {
            let client_id = secret.client_id.clone();
            state
                .audit
                .record(AuditEvent::new(
                    "admin".to_owned(),
                    None,
                    "client_secret_rotate".to_owned(),
                    "oauth_client".to_owned(),
                    Some(client_id.clone()),
                    serde_json::json!({"result": "success"}),
                ))
                .await;
            (StatusCode::OK, Json(secret)).into_response()
        }
        Err(ClientServiceError::InvalidData) => {
            error::bad_request("client_not_found", "client was not found")
        }
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to rotate OAuth client secret");
            error::internal()
        }
        Err(ClientServiceError::SecretHash) => error::internal(),
        Err(ClientServiceError::Validation(_)) => error::internal(),
        Err(ClientServiceError::QuotaExceeded) => error::internal(),
    }
}

async fn record_admin_event(state: &AppState, action: &str, client_id: &str) {
    state
        .audit
        .record(AuditEvent::new(
            "admin".to_owned(),
            None,
            action.to_owned(),
            "oauth_client".to_owned(),
            Some(client_id.to_owned()),
            serde_json::json!({"result": "success"}),
        ))
        .await;
}

pub(crate) fn is_admin_request(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    state.admin.is_authorization_header_valid(value)
}
