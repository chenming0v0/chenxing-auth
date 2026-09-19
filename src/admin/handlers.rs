use axum::{
    Json,
    extract::Path,
    extract::Query,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::client_errors::{
    delete_client_error_response, rotate_secret_error_response, set_client_status_error_response,
    update_client_error_response,
};
use crate::{
    admin::domain::AdminPermission,
    api::extract::{AdminRead, AdminWrite, ApiJson},
    audit::AuditEvent,
    clients::{
        domain::ClientRegistrationInput, idempotency::IdempotencyKey, service::ClientServiceError,
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
struct ClientSummary {
    id: i64,
    numeric_app_id: i64,
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    status: String,
    owner_user_id: Option<UserId>,
    auth_method: &'static str,
    logo_uri: Option<String>,
    client_uri: Option<String>,
    description: Option<String>,
    android_asset_link: Option<crate::clients::android_link::AndroidAssetLink>,
    quota_exempt: bool,
}

pub async fn list_clients(
    State(state): State<AppState>,
    admin: AdminRead,
    Query(query): Query<ClientListQuery>,
) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageClients)
        .await
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
                        numeric_app_id: client.numeric_app_id,
                        client_id: client.client_id,
                        client_name: client.client_name,
                        redirect_uris: client.redirect_uris,
                        scopes: client.scopes,
                        status: client.status,
                        owner_user_id: client.owner_user_id,
                        auth_method: client.auth_method.as_str(),
                        logo_uri: client.logo_uri,
                        client_uri: client.client_uri,
                        description: client.description,
                        android_asset_link: client.android_asset_link,
                        quota_exempt: client.quota_exempt,
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
    admin: AdminWrite,
    Path(client_id): Path<String>,
    ApiJson(input): ApiJson<ClientRegistrationInput>,
) -> Response {
    let authorization = match super::authorization::authorize_admin_write(
        &state,
        &admin,
        AdminPermission::ManageClients,
    )
    .await
    {
        Ok(authorization) => authorization,
        Err(response) => return response,
    };
    let actor = authorization.actor();
    let clients = crate::resource_services::scoped_client_service(&state, Some(&client_id)).await;
    match clients
        .update_with_audit(
            &client_id,
            input,
            AuditEvent::new(
                actor.actor_type().to_owned(),
                actor.user_id().map(|id| id.to_string()),
                crate::audit::AuditAction::ClientUpdate,
                "oauth_client".to_owned(),
                Some(client_id.clone()),
                serde_json::json!({"result": "success"}),
            ),
        )
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error::not_found("client_not_found", "client was not found"),
        Err(ClientServiceError::AuditUnavailable) => error::service_unavailable(
            "audit_unavailable",
            "the operation was rolled back because its audit record could not be written; retry later",
        ),
        Err(error_value) => update_client_error_response(&error_value),
    }
}

async fn set_client_status(
    state: AppState,
    admin: AdminWrite,
    client_id: String,
    status: &'static str,
) -> Response {
    let authorization = match super::authorization::authorize_admin_write(
        &state,
        &admin,
        AdminPermission::ManageClients,
    )
    .await
    {
        Ok(authorization) => authorization,
        Err(response) => return response,
    };
    let actor = authorization.actor();
    let action = match status {
        "active" => crate::audit::AuditAction::ClientActive,
        "disabled" => crate::audit::AuditAction::ClientDisabled,
        _ => unreachable!("client status is validated by the service"),
    };
    match state
        .clients
        .set_status_with_audit(
            &client_id,
            status,
            AuditEvent::new(
                actor.actor_type().to_owned(),
                actor.user_id().map(|id| id.to_string()),
                action,
                "oauth_client".to_owned(),
                Some(client_id.clone()),
                serde_json::json!({"result": "success"}),
            ),
        )
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error::not_found("client_not_found", "client was not found"),
        Err(ClientServiceError::AuditUnavailable) => error::service_unavailable(
            "audit_unavailable",
            "the operation was rolled back because its audit record could not be written; retry later",
        ),
        Err(error_value) => set_client_status_error_response(&error_value),
    }
}

pub async fn disable_client(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(client_id): Path<String>,
) -> Response {
    set_client_status(state, admin, client_id, "disabled").await
}

pub async fn enable_client(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(client_id): Path<String>,
) -> Response {
    set_client_status(state, admin, client_id, "active").await
}

pub async fn delete_client(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(client_id): Path<String>,
) -> Response {
    let authorization = match super::authorization::authorize_admin_write(
        &state,
        &admin,
        AdminPermission::ManageClients,
    )
    .await
    {
        Ok(authorization) => authorization,
        Err(response) => return response,
    };
    let actor = authorization.actor();
    match state
        .clients
        .delete_with_audit(
            &client_id,
            AuditEvent::new(
                actor.actor_type().to_owned(),
                actor.user_id().map(|id| id.to_string()),
                crate::audit::AuditAction::ClientDelete,
                "oauth_client".to_owned(),
                Some(client_id.clone()),
                serde_json::json!({"result": "success"}),
            ),
        )
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error::not_found("client_not_found", "client was not found"),
        Err(ClientServiceError::AuditUnavailable) => error::service_unavailable(
            "audit_unavailable",
            "the operation was rolled back because its audit record could not be written; retry later",
        ),
        Err(error_value) => delete_client_error_response(&error_value),
    }
}

pub async fn rotate_secret(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageClients)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let (actor_type, actor_id) = actor.audit_fields();
    let idempotency_key = match parse_idempotency_key(&headers) {
        Ok(key) => key,
        Err(()) => {
            return error::bad_request("invalid_idempotency_key", "idempotency key is invalid");
        }
    };
    let actor_scope = format!(
        "admin:{}:{}",
        actor_type,
        actor_id.as_deref().unwrap_or("system")
    );
    let result = match idempotency_key {
        Some(key) => {
            state
                .clients
                .rotate_secret_with_audit_idempotent(
                    &client_id,
                    actor_scope,
                    key,
                    AuditEvent::new(
                        actor_type.to_owned(),
                        actor_id,
                        crate::audit::AuditAction::ClientSecretRotate,
                        "oauth_client".to_owned(),
                        Some(client_id.clone()),
                        serde_json::json!({"result": "success"}),
                    ),
                )
                .await
        }
        None => {
            state
                .clients
                .rotate_secret_with_audit(
                    &client_id,
                    AuditEvent::new(
                        actor_type.to_owned(),
                        actor_id,
                        crate::audit::AuditAction::ClientSecretRotate,
                        "oauth_client".to_owned(),
                        Some(client_id.clone()),
                        serde_json::json!({"result": "success"}),
                    ),
                )
                .await
        }
    };
    match result {
        Ok(secret) => (StatusCode::OK, Json(secret)).into_response(),
        // 轮换冲突要留痕：这是并发轮换的可观测信号，响应体本身由映射函数给出，
        // 与直接走映射的路径保持同一个状态码和错误码。
        Err(error_value @ ClientServiceError::SecretRotationConflict) => {
            let (actor_type, actor_id) = actor.audit_fields();
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id,
                    crate::audit::AuditAction::ClientSecretRotateConflict,
                    "oauth_client".to_owned(),
                    Some(client_id.clone()),
                    serde_json::json!({
                        "result": "conflict",
                        "reason": "concurrent_rotation"
                    }),
                ))
                .await;
            rotate_secret_error_response(&error_value)
        }
        Err(ClientServiceError::AuditUnavailable) => {
            // #72 运维契约：一次性 Secret 签发被审计失败阻断时留下可检索的结构化事件。
            tracing::error!(
                event = "audit.block_on_failure",
                operation = "client_secret_rotate",
                "secret rotation rolled back because its audit record could not be written"
            );
            error::service_unavailable(
                "audit_unavailable",
                "the operation was rolled back because its audit record could not be written; retry later",
            )
        }
        Err(error_value) => rotate_secret_error_response(&error_value),
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

pub(super) fn parse_idempotency_key(headers: &HeaderMap) -> Result<Option<IdempotencyKey>, ()> {
    let Some(value) = headers.get("idempotency-key") else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?;
    IdempotencyKey::parse(value).map(Some).map_err(|_| ())
}
