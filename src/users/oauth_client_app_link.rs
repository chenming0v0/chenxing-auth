use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{
    admin::app_link_handlers::{AppLinkResponse, UpdateAppLinkInput},
    api::extract::{ApiJson, SessionWrite},
    audit::{AuditAction, AuditEvent},
    clients::{android_link::AndroidAssetLinkError, service::ClientServiceError},
    error,
    state::AppState,
};

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

fn not_found() -> Response {
    error::not_found("oauth_client_not_found", "OAuth project was not found")
}

pub async fn upsert_owned_client_app_link(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(client_id): Path<String>,
    ApiJson(input): ApiJson<UpdateAppLinkInput>,
) -> Response {
    match state
        .clients
        .upsert_app_link_for_user(
            session.user_id,
            &client_id,
            input.package_name,
            input.sha256_cert_fingerprints,
        )
        .await
    {
        Ok(Some(link)) => {
            let client = match state.clients.find_stored(&client_id).await {
                Ok(Some(client)) => client,
                Ok(None) => return not_found(),
                Err(error_value) => {
                    tracing::error!(error = %error_value, "failed to load client after app-link upsert");
                    return error::internal();
                }
            };
            let event = AuditEvent::new(
                "user".to_owned(),
                Some(session.user_id.to_string()),
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
        Ok(None) => not_found(),
        Err(ClientServiceError::AndroidLink(error)) => validation_response(&error),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to upsert owned app link");
            error::internal()
        }
    }
}

pub async fn delete_owned_client_app_link(
    State(state): State<AppState>,
    session: SessionWrite,
    Path(client_id): Path<String>,
) -> Response {
    match state
        .clients
        .delete_app_link_for_user(session.user_id, &client_id)
        .await
    {
        Ok(true) => {
            let event = AuditEvent::new(
                "user".to_owned(),
                Some(session.user_id.to_string()),
                AuditAction::ClientUpdate,
                "oauth_client".to_owned(),
                Some(client_id.clone()),
                serde_json::json!({"result": "success", "field": "android_asset_link", "cleared": true}),
            );
            let _ = state.audit.record(event).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to delete owned app link");
            error::internal()
        }
    }
}
