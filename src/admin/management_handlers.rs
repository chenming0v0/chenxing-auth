use crate::users::domain::UserId;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    authorization::{current_admin_mutation, current_admin_permission},
    domain::{AdminId, AdminPermission},
};
use crate::{error, state::AppState};

#[derive(Debug, Deserialize)]
pub struct LimitQuery {
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct AdminSummary {
    pub id: AdminId,
    pub username: String,
    pub role: &'static str,
    pub status: String,
}

pub async fn list_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageUsers).await
    {
        return response;
    }
    match state.users.list().await {
        Ok(users) => (
            StatusCode::OK,
            Json(
                users
                    .into_iter()
                    .map(|user| UserSummary {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        display_name: user.display_name,
                        status: user.status,
                        created_at: user.created_at,
                    })
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to list users");
            error::internal()
        }
    }
}

pub async fn set_user_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user_id, status)): Path<(UserId, String)>,
) -> Response {
    if let Err(response) =
        current_admin_mutation(&state, &headers, AdminPermission::ManageUsers).await
    {
        return response;
    }
    match state.users.set_status(user_id, &status).await {
        Ok(true) => {
            state
                .audit
                .record(crate::audit::AuditEvent::new(
                    "admin".to_owned(),
                    None,
                    format!("user_{status}"),
                    "user".to_owned(),
                    Some(user_id.to_string()),
                    serde_json::json!({"result":"success"}),
                ))
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::bad_request("user_not_found", "user or status was not found"),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to update user status");
            error::internal()
        }
    }
}

pub async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LimitQuery>,
) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ReadAudit).await
    {
        return response;
    }
    match state.audit.list(query.limit.unwrap_or(50)).await {
        Ok(events) => (StatusCode::OK, Json(events)).into_response(),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to list audit events");
            error::internal()
        }
    }
}

pub async fn list_admins(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageUsers).await
    {
        return response;
    }
    match state.admins.list().await {
        Ok(admins) => (
            StatusCode::OK,
            Json(
                admins
                    .into_iter()
                    .map(|(id, username, role, status)| AdminSummary {
                        id,
                        username,
                        role: role.as_str(),
                        status,
                    })
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list administrators");
            error::internal()
        }
    }
}
