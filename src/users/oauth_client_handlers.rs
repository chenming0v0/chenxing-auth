use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use super::ui_auth::{current_user, mutation_error, mutation_user};
use crate::{
    clients::{
        domain::ClientRegistrationInput,
        service::{ClientServiceError, ClientSummary, RegisteredClientSecret},
    },
    error,
    oauth::quota::QuotaSnapshot,
    state::AppState,
};

#[derive(Debug, Serialize)]
struct OwnedClientResponse {
    id: i64,
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    status: String,
    quota: QuotaSnapshot,
}

#[derive(Debug, Serialize)]
struct RegisteredOwnedClientResponse {
    #[serde(flatten)]
    client: OwnedClientResponse,
    client_secret: String,
}

#[derive(Debug, Serialize)]
struct OwnedClientListResponse {
    items: Vec<OwnedClientResponse>,
}

pub async fn list_owned_clients(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Ok(context) = current_user(&state, &headers).await else {
        return error::unauthorized("login_required", "an authenticated session is required");
    };
    let clients = match state.clients.list_for_user(context.user_id).await {
        Ok(clients) => clients,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list owned OAuth clients");
            return error::internal();
        }
    };
    match add_quota(&state, clients).await {
        Ok(items) => (StatusCode::OK, Json(OwnedClientListResponse { items })).into_response(),
        Err(response) => response,
    }
}

pub async fn create_owned_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ClientRegistrationInput>,
) -> Response {
    let Ok(context) = mutation_user(&state, &headers).await else {
        return mutation_error(&state, &headers).await;
    };
    match state
        .clients
        .register_for_user(context.user_id, input)
        .await
    {
        Ok(client) => match owned_registered_response(&state, client).await {
            Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
            Err(response) => response,
        },
        Err(ClientServiceError::Validation(validation_error)) => {
            error::bad_request("invalid_client_registration", validation_error.to_string())
        }
        Err(ClientServiceError::QuotaExceeded) => error::conflict(
            "oauth_client_quota_exceeded",
            "a normal user may own at most two OAuth projects",
        ),
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to create owned OAuth client");
            error::internal()
        }
        Err(ClientServiceError::SecretHash | ClientServiceError::InvalidData) => error::internal(),
    }
}

pub async fn update_owned_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(input): Json<ClientRegistrationInput>,
) -> Response {
    let Ok(context) = mutation_user(&state, &headers).await else {
        return mutation_error(&state, &headers).await;
    };
    match state
        .clients
        .update_for_user(context.user_id, &client_id, input)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error::not_found("oauth_client_not_found", "OAuth project was not found"),
        Err(ClientServiceError::Validation(validation_error)) => {
            error::bad_request("invalid_client_registration", validation_error.to_string())
        }
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to update owned OAuth client");
            error::internal()
        }
        Err(
            ClientServiceError::SecretHash
            | ClientServiceError::InvalidData
            | ClientServiceError::QuotaExceeded,
        ) => error::internal(),
    }
}

pub async fn disable_owned_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Response {
    set_owned_client_status(state, headers, client_id, "disabled").await
}

pub async fn enable_owned_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Response {
    set_owned_client_status(state, headers, client_id, "active").await
}

async fn set_owned_client_status(
    state: AppState,
    headers: HeaderMap,
    client_id: String,
    status: &str,
) -> Response {
    let Ok(context) = mutation_user(&state, &headers).await else {
        return mutation_error(&state, &headers).await;
    };
    match state
        .clients
        .set_status_for_user(context.user_id, &client_id, status)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error::not_found("oauth_client_not_found", "OAuth project was not found"),
        Err(ClientServiceError::InvalidData) => {
            error::bad_request("invalid_status", "status is invalid")
        }
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to update owned OAuth client status");
            error::internal()
        }
        Err(
            ClientServiceError::Validation(_)
            | ClientServiceError::SecretHash
            | ClientServiceError::QuotaExceeded,
        ) => error::internal(),
    }
}

pub async fn rotate_owned_client_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Response {
    let Ok(context) = mutation_user(&state, &headers).await else {
        return mutation_error(&state, &headers).await;
    };
    match state
        .clients
        .rotate_secret_for_user(context.user_id, &client_id)
        .await
    {
        Ok(secret) => (StatusCode::OK, Json(secret)).into_response(),
        Err(ClientServiceError::InvalidData) => {
            error::not_found("oauth_client_not_found", "OAuth project was not found")
        }
        Err(ClientServiceError::Database(database_error)) => {
            tracing::error!(error = %database_error, "failed to rotate owned OAuth client secret");
            error::internal()
        }
        Err(
            ClientServiceError::SecretHash
            | ClientServiceError::Validation(_)
            | ClientServiceError::QuotaExceeded,
        ) => error::internal(),
    }
}

async fn add_quota(
    state: &AppState,
    clients: Vec<ClientSummary>,
) -> Result<Vec<OwnedClientResponse>, Response> {
    let mut items = Vec::with_capacity(clients.len());
    for client in clients {
        let quota = state
            .oauth_quotas
            .snapshot(&client.client_id)
            .await
            .map_err(|_| error::internal())?;
        items.push(OwnedClientResponse {
            id: client.id,
            client_id: client.client_id,
            client_name: client.client_name,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
            status: client.status,
            quota,
        });
    }
    Ok(items)
}

async fn owned_registered_response(
    state: &AppState,
    client: RegisteredClientSecret,
) -> Result<RegisteredOwnedClientResponse, Response> {
    let quota = state
        .oauth_quotas
        .snapshot(&client.client_id)
        .await
        .map_err(|_| error::internal())?;
    Ok(RegisteredOwnedClientResponse {
        client: OwnedClientResponse {
            id: client.id,
            client_id: client.client_id,
            client_name: client.client_name,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
            status: "active".to_owned(),
            quota,
        },
        client_secret: client.client_secret,
    })
}
