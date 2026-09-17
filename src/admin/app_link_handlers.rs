//! App Links（Android App Links）管理面：Owner 把任意 Client 发布到本 Issuer 主机。

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    admin::domain::AdminPermission,
    api::extract::{AdminRead, AdminWrite},
    audit::{AuditAction, AuditEvent},
    clients::{android_link::AndroidAssetLinkError, repository::StoredClient},
    error,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct UpdateAppLinkInput {
    pub package_name: String,
    pub sha256_cert_fingerprints: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AppLinkResponse {
    pub client_id: String,
    pub numeric_app_id: i64,
    pub client_name: String,
    pub package_name: String,
    pub sha256_cert_fingerprints: Vec<String>,
}

fn validation_response(error: &AndroidAssetLinkError) -> Response {
    match error {
        AndroidAssetLinkError::InvalidPackageName => error::bad_request(
            "invalid_android_package_name",
            "Android package name is invalid",
        ),
        AndroidAssetLinkError::InvalidFingerprint => error::bad_request(
            "invalid_android_fingerprint",
            "Android SHA-256 certificate fingerprint is invalid",
        ),
    }
}

async fn require_client(state: &AppState, client_id: &str) -> Result<StoredClient, Response> {
    match state.clients.find_stored(client_id).await {
        Ok(Some(client)) => Ok(client),
        Ok(None) => Err(error::not_found(
            "oauth_client_not_found",
            "OAuth project was not found",
        )),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load client for app link");
            Err(error::internal())
        }
    }
}

/// 列出 Owner 已发布到本 Issuer 的 App Link（带当前指纹）。
#[axum::debug_handler]
pub async fn list_app_links(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin.authorize(&state, AdminPermission::ManageIssuer).await {
        return response;
    }
    match state.clients.declared_app_links().await {
        Ok(items) => (
            StatusCode::OK,
            Json(
                items
                    .into_iter()
                    .map(|item| AppLinkResponse {
                        client_id: item.client_id,
                        numeric_app_id: item.numeric_app_id,
                        client_name: item.client_name,
                        package_name: item.package_name,
                        sha256_cert_fingerprints: item.sha256_cert_fingerprints,
                    })
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to list app links");
            error::internal()
        }
    }
}

/// 用给定的包名和指纹替换该 Client 的 App Link 声明。
#[axum::debug_handler]
pub async fn upsert_app_link(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(client_id): Path<String>,
    Json(input): Json<UpdateAppLinkInput>,
) -> Response {
    let actor = match admin.authorize(&state, AdminPermission::ManageIssuer).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let client = match require_client(&state, &client_id).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    match state
        .clients
        .upsert_app_link(
            &client_id,
            input.package_name,
            input.sha256_cert_fingerprints,
        )
        .await
    {
        Ok(Some(link)) => {
            let (actor_type, actor_id) = actor.audit_fields();
            let event = AuditEvent::new(
                actor_type.to_owned(),
                actor_id,
                AuditAction::ClientUpdate,
                "oauth_client".to_owned(),
                Some(client_id.clone()),
                serde_json::json!({"result": "success", "field": "android_asset_link"}),
            );
            let _ = state.audit.record(event).await;
            (
                StatusCode::OK,
                Json(AppLinkResponse {
                    client_id,
                    numeric_app_id: client.numeric_app_id,
                    client_name: client.client_name,
                    package_name: link.package_name,
                    sha256_cert_fingerprints: link.sha256_cert_fingerprints,
                }),
            )
                .into_response()
        }
        Ok(None) => error::not_found("oauth_client_not_found", "OAuth project was not found"),
        Err(crate::clients::service::ClientServiceError::AndroidLink(error)) => {
            validation_response(&error)
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to upsert app link");
            error::internal()
        }
    }
}

/// 清空一个 Client 的 App Link 声明，公开 DAL 同步撤下。
#[axum::debug_handler]
pub async fn delete_app_link(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(client_id): Path<String>,
) -> Response {
    let actor = match admin.authorize(&state, AdminPermission::ManageIssuer).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = require_client(&state, &client_id).await {
        return response;
    }
    match state.clients.delete_app_link(&client_id).await {
        Ok(true) => {
            let (actor_type, actor_id) = actor.audit_fields();
            let event = AuditEvent::new(
                actor_type.to_owned(),
                actor_id,
                AuditAction::ClientUpdate,
                "oauth_client".to_owned(),
                Some(client_id.clone()),
                serde_json::json!({"result": "success", "field": "android_asset_link", "cleared": true}),
            );
            let _ = state.audit.record(event).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::not_found("oauth_client_not_found", "OAuth project was not found"),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to delete app link");
            error::internal()
        }
    }
}
