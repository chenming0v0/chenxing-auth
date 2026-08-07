use crate::users::domain::{UserId, UserRole, UserStatus};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    authorization::{AdminActor, current_admin_mutation, current_admin_permission},
    domain::AdminPermission,
};
use crate::{error, state::AppState};

/// list_users 默认返回条数（未提供 limit 查询参数时）。
const DEFAULT_USER_LIST_LIMIT: i64 = 50;
/// list_users 最大返回条数，与 AuditService::list 保持一致。
const MAX_USER_LIST_LIMIT: i64 = 200;

#[derive(Debug, Deserialize)]
pub struct LimitQuery {
    pub limit: Option<i64>,
}

/// list_users 专用查询参数，支持可选分页。
#[derive(Debug, Deserialize)]
pub struct UserListQuery {
    /// 返回条数，默认 50，最大 200，超限自动 clamp。
    pub limit: Option<i64>,
    /// 跳过条数，默认 0，用于手动翻页。
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct SetUserRoleInput {
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
    pub role: UserRole,
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct AdminSummary {
    pub id: UserId,
    pub username: String,
    pub role: &'static str,
    pub status: String,
}

pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UserListQuery>,
) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageUsers).await
    {
        return response;
    }
    // 无上限列表会把整张用户表（含 email）在单次响应里倾倒出去，
    // 因此在数据库层强制 LIMIT/OFFSET；上限与 AuditService::list 保持一致。
    let limit = query
        .limit
        .unwrap_or(DEFAULT_USER_LIST_LIMIT)
        .clamp(1, MAX_USER_LIST_LIMIT);
    let offset = query.offset.unwrap_or(0).max(0);
    // 复用已分页的 query 用例，避免给无上限的 list 路径继续打补丁。
    match state.users.query(None, None, limit, offset).await {
        Ok((users, _total)) => (
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
                        role: user.role,
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
    let actor = match current_admin_mutation(&state, &headers, AdminPermission::ManageUsers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    // The service uses `false` for both an invalid status and a missing user.
    // Preserve the existing validation response so only a missing resource becomes 404.
    if UserStatus::parse(&status).is_none() {
        return error::bad_request("user_not_found", "user or status was not found");
    }
    match state.users.set_status_guarded(user_id, &status).await {
        Ok(true) => {
            let (actor_type, actor_id) = actor.audit_fields();
            if state
                .audit
                .record(crate::audit::AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id,
                    format!("user_{status}"),
                    "user".to_owned(),
                    Some(user_id.to_string()),
                    serde_json::json!({"result":"success"}),
                ))
                .await
                .is_err()
            {
                return error::internal();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::not_found("user_not_found", "user was not found"),
        Err(crate::users::service::UserServiceError::LastOwnerRequired) => error::conflict(
            "last_owner_required",
            "at least one active owner is required",
        ),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to update user status");
            error::internal()
        }
    }
}

pub async fn set_user_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<UserId>,
    Json(input): Json<SetUserRoleInput>,
) -> Response {
    let actor = match current_admin_mutation(&state, &headers, AdminPermission::ManageRoles).await {
        Ok(actor_id) => actor_id,
        Err(response) => return response,
    };
    if actor == AdminActor::User(user_id) {
        return error::forbidden(
            "self_role_change_forbidden",
            "users cannot change their own role",
        );
    }
    let Some(role) = UserRole::parse(&input.role) else {
        return error::bad_request("invalid_role", "role is invalid");
    };
    match state.users.set_role(user_id, role).await {
        Ok(true) => {
            let (actor_type, actor_id) = actor.audit_fields();
            if state
                .audit
                .record(crate::audit::AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id,
                    "user_role_update".to_owned(),
                    "user".to_owned(),
                    Some(user_id.to_string()),
                    serde_json::json!({"role": role.as_str()}),
                ))
                .await
                .is_err()
            {
                return error::internal();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::not_found("user_not_found", "user was not found"),
        Err(crate::users::service::UserServiceError::LastOwnerRequired) => error::conflict(
            "last_owner_required",
            "at least one active owner is required",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update user role");
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
    match state.users.list_administrators().await {
        Ok(users) => (
            StatusCode::OK,
            Json(
                users
                    .into_iter()
                    .map(|user| AdminSummary {
                        id: user.id,
                        username: user.username,
                        role: user.role.as_str(),
                        status: user.status,
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
