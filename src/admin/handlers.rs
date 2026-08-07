use axum::{
    Json,
    extract::Path,
    extract::Query,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    admin::{
        authorization::{current_admin_mutation, current_admin_permission},
        domain::AdminPermission,
    },
    audit::AuditEvent,
    clients::{
        domain::ClientRegistrationInput,
        service::{ClientRegistrationRequest, ClientServiceError},
    },
    error,
    state::AppState,
    users::domain::UserId,
};

/// list_clients 专用查询参数，支持可选分页（Issue #67）。
#[derive(Debug, Deserialize)]
pub struct ClientListQuery {
    /// 返回条数，默认 50，最大 200，超限自动 clamp。
    pub limit: Option<i64>,
    /// 跳过条数，默认 0，用于手动翻页。
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
struct RegisteredClientResponse {
    id: i64,
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    /// Client 认证方式；`none` 表示公开客户端，响应不含 client_secret。
    auth_method: &'static str,
    /// 公开客户端不签发 secret，此时该字段整体省略（Issue #66）。
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
struct ClientSummary {
    id: i64,
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    status: String,
    owner_user_id: Option<UserId>,
}

pub async fn create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ClientRegistrationRequest>,
) -> Response {
    let actor = match current_admin_mutation(&state, &headers, AdminPermission::ManageClients).await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };

    match state.clients.register(input).await {
        Ok(client) => {
            let client_id = client.client_id.clone();
            let (actor_type, actor_id) = actor.audit_fields();
            // 必须先写审计，审计成功后才把凭据返回给调用者。
            // 若审计失败：client 记录已在数据库提交，但调用者拿不到 secret，
            // 攻击者无法利用未被记录的凭据；运维可凭结构化日志人工补账。
            if let Err(audit_err) = state
                .audit
                .record(AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id.clone(),
                    "client_create".to_owned(),
                    "oauth_client".to_owned(),
                    Some(client_id.clone()),
                    serde_json::json!({"result": "success"}),
                ))
                .await
            {
                tracing::error!(
                    event = "audit.block_on_failure",
                    action = "client_create",
                    client_id = %client_id,
                    actor_id = ?actor_id,
                    error = %audit_err,
                    "审计写入失败；client 已创建但 secret 未返回，可凭 client_id 人工补账"
                );
                return error::internal();
            }
            (
                axum::http::StatusCode::CREATED,
                Json(RegisteredClientResponse {
                    id: client.id,
                    client_id: client.client_id,
                    client_name: client.client_name,
                    redirect_uris: client.redirect_uris,
                    scopes: client.scopes,
                    auth_method: client.auth_method.as_str(),
                    client_secret: client.client_secret,
                }),
            )
                .into_response()
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

pub async fn list_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientListQuery>,
) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageClients).await
    {
        return response;
    }
    // 无上限列表会把整张 Client 表在单次响应里倾倒出去，
    // 因此在数据库层强制 LIMIT/OFFSET；上限与 list_users 保持一致（Issue #67）。
    match state.clients.list(query.limit, query.offset).await {
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
    let actor = match current_admin_mutation(&state, &headers, AdminPermission::ManageClients).await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match state.clients.update(&client_id, input).await {
        Ok(true) => {
            let (actor_type, actor_id) = actor.audit_fields();
            if state
                .audit
                .record(AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id,
                    "client_update".to_owned(),
                    "oauth_client".to_owned(),
                    Some(client_id.clone()),
                    serde_json::json!({"result": "success"}),
                ))
                .await
                .is_err()
            {
                return error::internal();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::not_found("client_not_found", "client was not found"),
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
    let actor = match current_admin_mutation(&state, &headers, AdminPermission::ManageClients).await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match state.clients.set_status(&client_id, status).await {
        Ok(true) => {
            let (actor_type, actor_id) = actor.audit_fields();
            if state
                .audit
                .record(AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id,
                    format!("client_{status}"),
                    "oauth_client".to_owned(),
                    Some(client_id.clone()),
                    serde_json::json!({"result": "success"}),
                ))
                .await
                .is_err()
            {
                return error::internal();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::not_found("client_not_found", "client was not found"),
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
    let actor = match current_admin_mutation(&state, &headers, AdminPermission::ManageClients).await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match state.clients.rotate_secret(&client_id).await {
        Ok(secret) => {
            let client_id = secret.client_id.clone();
            let (actor_type, actor_id) = actor.audit_fields();
            // 与 create_client 一致：先写审计，审计成功后才返回新 secret。
            // 若审计失败：旧 secret 已在数据库失效，但调用者拿不到新 secret，
            // 该 client 暂时无法认证；运维可凭结构化日志人工补账或再次轮换。
            if let Err(audit_err) = state
                .audit
                .record(AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id.clone(),
                    "client_secret_rotate".to_owned(),
                    "oauth_client".to_owned(),
                    Some(client_id.clone()),
                    serde_json::json!({"result": "success"}),
                ))
                .await
            {
                tracing::error!(
                    event = "audit.block_on_failure",
                    action = "client_secret_rotate",
                    client_id = %client_id,
                    actor_id = ?actor_id,
                    error = %audit_err,
                    "审计写入失败；secret 已轮换但新 secret 未返回，可凭 client_id 人工补账"
                );
                return error::internal();
            }
            (StatusCode::OK, Json(secret)).into_response()
        }
        Err(ClientServiceError::InvalidData) => {
            error::not_found("client_not_found", "client was not found")
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

pub(crate) fn is_admin_request(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    state.admin.is_authorization_header_valid(value)
}
