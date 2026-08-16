use crate::users::domain::{UserId, UserRole, UserStatus};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    authorization::{
        OwnerGuardedOperation, authorize_user_write, management_actor_permission_denied,
        management_actor_session_invalid, owner_write_permission_denied, record_owner_guard_denial,
    },
    domain::AdminPermission,
};
use crate::{
    api::extract::{AdminRead, AdminWrite, ApiJson},
    error,
    state::AppState,
};

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
    #[serde(with = "time::serde::rfc3339")]
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
    admin: AdminRead,
    Query(query): Query<UserListQuery>,
) -> Response {
    if let Err(response) = admin.authorize(&state, AdminPermission::ManageUsers).await {
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

/// `POST /api/v1/admin/users/{user_id}/{status}`。
///
/// 顺序固定为：基线 `ManageUsers` → 自我操作检查 → 解析状态 → 写事务锁住目标并判定 Owner 档位。
/// 目标角色与状态写入共用事务，消除并发晋升 Owner 的旧快照窗口（Issue #323）。
/// 用户 Session actor 的 active、role 与 generation 也在同一事务内锁定复核；
/// handler 的初始授权只负责快速拒绝与 CSRF，不能授权最终提交（Issue #493）。
/// 状态串是与资源无关的语法输入，在查询目标之前解析，因此非法状态恒为
/// 400 `invalid_status`，不再和「用户不存在」共用一个错误码（Issue #283）。
pub async fn set_user_status(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path((user_id, status)): Path<(UserId, String)>,
) -> Response {
    let authorization = match authorize_user_write(&state, &admin).await {
        Ok(authorization) => authorization,
        Err(response) => return response,
    };
    let actor = authorization.actor();
    // 自我操作保护：把 `disabled` 落到自己身上会在事务内撤销自己的全部会话，
    // 立即失去管理面且无自助恢复路径，与 set_user_role 的自我角色检查保持一致（Issue #336）。
    if actor.user_id() == Some(user_id) {
        return error::forbidden(
            "self_status_change_forbidden",
            "users cannot change their own status",
        );
    }
    let Some(status) = UserStatus::parse(&status) else {
        return error::bad_request("invalid_status", "status is invalid");
    };
    match state
        .users
        .set_status_guarded(user_id, status, authorization.credential())
        .await
    {
        Ok(true) => {
            let (actor_type, actor_id) = actor.audit_fields();
            state
                .audit
                .record_best_effort(crate::audit::AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id,
                    match status {
                        UserStatus::Active => crate::audit::AuditAction::UserActive,
                        UserStatus::Disabled => crate::audit::AuditAction::UserDisabled,
                    },
                    "user".to_owned(),
                    Some(user_id.to_string()),
                    serde_json::json!({"result":"success"}),
                ))
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        // 状态串已在上面解析过，`false` 只剩一种含义：目标用户不存在。
        Ok(false) => error::not_found("user_not_found", "user was not found"),
        // 有权限的调用者试图禁用最后一个活跃 Owner：这是安全相关决策，必须留痕（Issue #304）。
        Err(crate::users::service::ManagementWriteError::LastOwnerRequired) => {
            record_owner_guard_denial(
                &state,
                actor,
                user_id,
                OwnerGuardedOperation::UserStatusUpdate,
                status.as_str(),
            )
            .await;
            error::conflict(
                "last_owner_required",
                "at least one active owner is required",
            )
        }
        Err(crate::users::service::ManagementWriteError::ManageRolesRequired) => {
            owner_write_permission_denied(&state, authorization).await
        }
        Err(crate::users::service::ManagementWriteError::ActorSessionInvalid) => {
            management_actor_session_invalid(&state, authorization).await
        }
        Err(crate::users::service::ManagementWriteError::ActorPermissionRequired) => {
            management_actor_permission_denied(&state, authorization).await
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to update user status");
            error::internal()
        }
    }
}

pub async fn set_user_role(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(user_id): Path<UserId>,
    ApiJson(input): ApiJson<SetUserRoleInput>,
) -> Response {
    let authorization = match authorize_user_write(&state, &admin).await {
        Ok(authorization) => authorization,
        Err(response) => return response,
    };
    let actor = authorization.actor();
    if actor.user_id() == Some(user_id) {
        return error::forbidden(
            "self_role_change_forbidden",
            "users cannot change their own role",
        );
    }
    let Some(role) = UserRole::parse(&input.role) else {
        return error::bad_request("invalid_role", "role is invalid");
    };
    match state
        .users
        .set_role(user_id, role, authorization.credential())
        .await
    {
        Ok(true) => {
            let (actor_type, actor_id) = actor.audit_fields();
            state
                .audit
                .record_best_effort(crate::audit::AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id,
                    crate::audit::AuditAction::UserRoleUpdate,
                    "user".to_owned(),
                    Some(user_id.to_string()),
                    serde_json::json!({"role": role.as_str()}),
                ))
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error::not_found("user_not_found", "user was not found"),
        // 降级最后一个活跃 Owner 与禁用它同档，走同一条留痕路径（Issue #304）。
        Err(crate::users::service::ManagementWriteError::LastOwnerRequired) => {
            record_owner_guard_denial(
                &state,
                actor,
                user_id,
                OwnerGuardedOperation::UserRoleUpdate,
                role.as_str(),
            )
            .await;
            error::conflict(
                "last_owner_required",
                "at least one active owner is required",
            )
        }
        Err(crate::users::service::ManagementWriteError::ManageRolesRequired) => {
            owner_write_permission_denied(&state, authorization).await
        }
        Err(crate::users::service::ManagementWriteError::ActorSessionInvalid) => {
            management_actor_session_invalid(&state, authorization).await
        }
        Err(crate::users::service::ManagementWriteError::ActorPermissionRequired) => {
            management_actor_permission_denied(&state, authorization).await
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update user role");
            error::internal()
        }
    }
}

pub async fn list_audit(
    State(state): State<AppState>,
    admin: AdminRead,
    Query(query): Query<LimitQuery>,
) -> Response {
    if let Err(response) = admin.authorize(&state, AdminPermission::ReadAudit).await {
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

pub async fn list_admins(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin.authorize(&state, AdminPermission::ManageUsers).await {
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

#[cfg(test)]
mod tests {
    use super::UserSummary;
    use crate::users::domain::UserRole;

    #[test]
    fn management_user_summary_serializes_creation_time_as_rfc3339() {
        let value = serde_json::to_value(UserSummary {
            id: 1,
            username: "owner".to_owned(),
            email: "owner@example.test".to_owned(),
            display_name: None,
            status: "active".to_owned(),
            role: UserRole::Owner,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        })
        .expect("user summary serializes");

        assert_eq!(value["created_at"], "1970-01-01T00:00:00Z");
    }
}
