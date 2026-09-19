use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::fmt;

use super::{
    authorization::AdminActor, client_errors::create_client_error_response,
    domain::AdminPermission, handlers::parse_idempotency_key,
};
use crate::{
    api::extract::{AdminWrite, ApiJson},
    audit::AuditEvent,
    clients::service::{ClientRegistrationRequest, ClientServiceError},
    error,
    state::AppState,
};

#[derive(serde::Serialize)]
struct RegisteredClientResponse {
    id: i64,
    numeric_app_id: i64,
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    /// Client 认证方式；`none` 表示公开客户端，响应不含 client_secret。
    auth_method: &'static str,
    /// 公开客户端不签发 secret，此时该字段整体省略（Issue #66）。
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    logo_uri: Option<String>,
    client_uri: Option<String>,
    description: Option<String>,
    android_asset_link: Option<crate::clients::android_link::AndroidAssetLink>,
    quota_exempt: bool,
}

impl fmt::Debug for RegisteredClientResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredClientResponse")
            .field("id", &self.id)
            .field("client_id", &self.client_id)
            .field("client_name", &self.client_name)
            .field("redirect_uris", &self.redirect_uris)
            .field("scopes", &self.scopes)
            .field("auth_method", &self.auth_method)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("logo_uri", &self.logo_uri)
            .field("client_uri", &self.client_uri)
            .field("description", &self.description)
            .finish()
    }
}

async fn owner_for_admin_client(
    state: &AppState,
    actor: AdminActor,
) -> Result<Option<crate::users::domain::UserId>, Response> {
    match actor {
        AdminActor::User(user_id) => Ok(Some(user_id)),
        AdminActor::SystemToken => crate::users::repository::first_active_owner_id(&state.database)
            .await
            .map_err(|error_value| {
                tracing::error!(
                    error = %error_value,
                    "failed to resolve owner for admin-created OAuth client"
                );
                error::internal()
            }),
    }
}

pub async fn create_client(
    State(state): State<AppState>,
    admin: AdminWrite,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ClientRegistrationRequest>,
) -> Response {
    let actor = match admin
        .authorize(&state, AdminPermission::ManageClients)
        .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };

    let owner_user_id = match owner_for_admin_client(&state, actor).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let (actor_type, actor_id) = actor.audit_fields();
    let idempotency_key = match parse_idempotency_key(&headers) {
        Ok(key) => key,
        Err(()) => {
            return error::bad_request("invalid_idempotency_key", "idempotency key is invalid");
        }
    };
    // 新应用尚无 client_id：allowlist = 基础 scope + public 资源服务 scope。
    let clients = crate::resource_services::scoped_client_service(&state, None).await;
    let result = match idempotency_key {
        Some(key) => {
            let actor_scope = format!(
                "admin:{}:{}",
                actor_type,
                actor_id.as_deref().unwrap_or("system")
            );
            clients
                .register_with_audit_idempotent(
                    owner_user_id,
                    input,
                    actor_scope,
                    key,
                    move |client| {
                        AuditEvent::new(
                            actor_type.to_owned(),
                            actor_id,
                            crate::audit::AuditAction::ClientCreate,
                            "oauth_client".to_owned(),
                            Some(client.client_id.clone()),
                            serde_json::json!({"result": "success"}),
                        )
                    },
                )
                .await
        }
        None => {
            clients
                .register_with_audit(owner_user_id, input, move |client| {
                    AuditEvent::new(
                        actor_type.to_owned(),
                        actor_id,
                        crate::audit::AuditAction::ClientCreate,
                        "oauth_client".to_owned(),
                        Some(client.client_id.clone()),
                        serde_json::json!({"result": "success"}),
                    )
                })
                .await
        }
    };
    match result {
        Ok(client) => (
            axum::http::StatusCode::CREATED,
            Json(RegisteredClientResponse {
                id: client.id,
                numeric_app_id: client.numeric_app_id,
                client_id: client.client_id,
                client_name: client.client_name,
                redirect_uris: client.redirect_uris,
                scopes: client.scopes,
                auth_method: client.auth_method.as_str(),
                client_secret: client.client_secret,
                logo_uri: client.logo_uri,
                client_uri: client.client_uri,
                description: client.description,
                android_asset_link: client.android_asset_link,
                quota_exempt: true,
            }),
        )
            .into_response(),
        Err(ClientServiceError::AuditUnavailable) => {
            // #72 运维契约：凭据签发被审计失败阻断时留下可检索的结构化事件。
            tracing::error!(
                event = "audit.block_on_failure",
                operation = "client_create",
                "client creation rolled back because its audit record could not be written"
            );
            error::service_unavailable(
                "audit_unavailable",
                "the operation was rolled back because its audit record could not be written; retry later",
            )
        }
        Err(error_value) => create_client_error_response(&error_value),
    }
}
