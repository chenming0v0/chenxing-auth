use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::{
    authorization::{
        authorize_admin_write, authorize_user_write, management_actor_permission_denied,
        management_actor_session_invalid, management_actor_validation_failed,
        owner_write_permission_denied,
    },
    domain::AdminPermission,
};
use crate::{
    api::extract::{AdminRead, AdminWrite, ApiJson},
    audit::AuditEvent,
    error,
    plans::{
        domain::PlanInput,
        service::{PlanServiceError, PlanWithUsers},
    },
    state::AppState,
    users::domain::UserId,
};

#[derive(Debug, Serialize)]
struct PlanResponse {
    #[serde(flatten)]
    plan: crate::plans::domain::Plan,
    assigned_users: i64,
}

fn plan_response(plan: crate::plans::domain::Plan, assigned_users: i64) -> PlanResponse {
    PlanResponse {
        plan,
        assigned_users,
    }
}

pub async fn list_plans(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin
        .authorize(&state, AdminPermission::ManageSettings)
        .await
    {
        return response;
    }
    match state.plans.list().await {
        Ok(plans) => (
            StatusCode::OK,
            Json(
                plans
                    .into_iter()
                    .map(
                        |PlanWithUsers {
                             plan,
                             assigned_users,
                         }| plan_response(plan, assigned_users),
                    )
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list plans");
            error::internal()
        }
    }
}

pub async fn create_plan(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(input): ApiJson<PlanInput>,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageSettings).await {
            Ok(authorization) => authorization,
            Err(response) => return response,
        };
    let actor = authorization.actor();
    let (actor_type, actor_id) = actor.audit_fields();
    let event = AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        crate::audit::AuditAction::PlanCreate,
        "plan".to_owned(),
        Some(input.code.clone()),
        serde_json::json!({"result": "success"}),
    );
    match state
        .plans
        .create(input, authorization.credential(), event)
        .await
    {
        Ok(plan) => {
            // 新建套餐尚无分配用户，直接返回 0
            (StatusCode::CREATED, Json(plan_response(plan, 0))).into_response()
        }
        Err(PlanServiceError::ManagementActor(error_value)) => {
            management_actor_validation_failed(&state, authorization, error_value).await
        }
        Err(error_value) => plan_error_response(error_value),
    }
}

pub async fn update_plan(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(id): Path<i64>,
    ApiJson(input): ApiJson<PlanInput>,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageSettings).await {
            Ok(authorization) => authorization,
            Err(response) => return response,
        };
    let actor = authorization.actor();
    let (actor_type, actor_id) = actor.audit_fields();
    let event = AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        crate::audit::AuditAction::PlanUpdate,
        "plan".to_owned(),
        Some(input.code.clone()),
        serde_json::json!({"result": "success"}),
    );
    match state
        .plans
        .update(id, input, authorization.credential(), event)
        .await
    {
        Ok(updated) => {
            // assigned_users 由 repository.update 在同一事务中统计，与 list_plans 行为一致
            let response = plan_response(updated.plan, updated.assigned_users);
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(PlanServiceError::ManagementActor(error_value)) => {
            management_actor_validation_failed(&state, authorization, error_value).await
        }
        Err(error_value) => plan_error_response(error_value),
    }
}

pub async fn archive_plan(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(id): Path<i64>,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageSettings).await {
            Ok(authorization) => authorization,
            Err(response) => return response,
        };
    let actor = authorization.actor();
    let (actor_type, actor_id) = actor.audit_fields();
    let event = AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        crate::audit::AuditAction::PlanArchive,
        "plan".to_owned(),
        Some(id.to_string()),
        serde_json::json!({"result": "success"}),
    );
    let result = state
        .plans
        .archive(id, authorization.credential(), event)
        .await;
    finish_plan_status_change(
        &state,
        authorization,
        result,
        crate::audit::AuditAction::PlanArchive,
        &id.to_string(),
    )
    .await
}

pub async fn restore_plan(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(id): Path<i64>,
) -> Response {
    let authorization =
        match authorize_admin_write(&state, &admin, AdminPermission::ManageSettings).await {
            Ok(authorization) => authorization,
            Err(response) => return response,
        };
    let actor = authorization.actor();
    let (actor_type, actor_id) = actor.audit_fields();
    let event = AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        crate::audit::AuditAction::PlanRestore,
        "plan".to_owned(),
        Some(id.to_string()),
        serde_json::json!({"result": "success"}),
    );
    let result = state
        .plans
        .restore(id, authorization.credential(), event)
        .await;
    finish_plan_status_change(
        &state,
        authorization,
        result,
        crate::audit::AuditAction::PlanRestore,
        &id.to_string(),
    )
    .await
}

/// 套餐状态变更的公共后处理：审计记录 + 响应。
/// 接收已确定的操作结果，消除字符串选择操作的分发模式。
async fn finish_plan_status_change(
    state: &AppState,
    authorization: super::authorization::AdminWriteAuthorization,
    result: Result<(), PlanServiceError>,
    _action: crate::audit::AuditAction,
    _resource_id: &str,
) -> Response {
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(PlanServiceError::ManagementActor(error_value)) => {
            management_actor_validation_failed(state, authorization, error_value).await
        }
        Err(error_value) => plan_error_response(error_value),
    }
}

#[derive(Debug, Deserialize)]
pub struct AssignPlanInput {
    pub plan_id: i64,
    /// `null` 表示永久有效；RFC3339 字符串或 time 的 tuple 形式均可。
    pub expires_at: Option<Value>,
}

/// `POST /api/v1/admin/users/{user_id}/plan`。
///
/// 分配套餐直接改写用户权益（entitlements），语义属于用户管理而非系统设置，
/// 因此基线是 `ManageUsers` 而不是 `ManageSettings` —— 只有系统设置权限的角色
/// 不得改写任意用户的套餐。目标是 Owner 时门槛抬到 `ManageRoles`：改写 Owner
/// 的权益能压缩最高权限持有者的 Client 配额与授权额度，与禁用 Owner 同档
/// （Issue #280）。Owner 判定与套餐写入现在共用目标用户行锁（Issue #323），
/// 不再依赖事务外的角色预读。
pub async fn assign_plan(
    State(state): State<AppState>,
    admin: AdminWrite,
    Path(user_id): Path<UserId>,
    ApiJson(input): ApiJson<AssignPlanInput>,
) -> Response {
    let authorization = match authorize_user_write(&state, &admin).await {
        Ok(authorization) => authorization,
        Err(response) => return response,
    };
    let actor = authorization.actor();
    let expires_at = match parse_expiry(input.expires_at) {
        Ok(expires_at) => expires_at,
        Err(message) => return error::bad_request("invalid_expiration", message),
    };
    let event = AuditEvent::new(
        actor.actor_type().to_owned(),
        actor.user_id().map(|id| id.to_string()),
        crate::audit::AuditAction::UserPlanAssign,
        "user".to_owned(),
        Some(user_id.to_string()),
        serde_json::json!({"result": "success"}),
    );
    match state
        .plans
        .assign_to_user(
            user_id,
            input.plan_id,
            expires_at,
            authorization.credential(),
            event,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(PlanServiceError::ManageRolesRequired) => {
            owner_write_permission_denied(&state, authorization).await
        }
        Err(PlanServiceError::ActorSessionInvalid) => {
            management_actor_session_invalid(&state, authorization).await
        }
        Err(PlanServiceError::ActorPermissionRequired) => {
            management_actor_permission_denied(&state, authorization).await
        }
        Err(error_value) => plan_error_response(error_value),
    }
}

fn parse_expiry(value: Option<Value>) -> Result<Option<OffsetDateTime>, &'static str> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        Value::String(text) => {
            OffsetDateTime::parse(&text, &time::format_description::well_known::Rfc3339)
                .map(Some)
                .map_err(|_| "expires_at must be an RFC3339 timestamp")
        }
        value => serde_json::from_value::<OffsetDateTime>(value)
            .map(Some)
            .map_err(|_| "expires_at is invalid"),
    }
}

fn plan_error_response(error_value: PlanServiceError) -> Response {
    match error_value {
        PlanServiceError::Validation(validation_error) => {
            error::bad_request("invalid_plan", validation_error.to_string())
        }
        PlanServiceError::NotFound => error::not_found("plan_not_found", "plan was not found"),
        PlanServiceError::CodeConflict => {
            error::conflict("plan_code_conflict", "plan code is already registered")
        }
        PlanServiceError::ArchivedPlanCannotBeDefault => {
            error::conflict("archived_plan_default", "archived plans cannot be default")
        }
        PlanServiceError::PlanArchived => error::bad_request(
            "plan_archived",
            "archived plans cannot be assigned to users",
        ),
        PlanServiceError::UserNotFound => error::not_found("user_not_found", "user was not found"),
        PlanServiceError::ManageRolesRequired => {
            tracing::error!("owner permission outcome escaped the assignment handler");
            error::internal()
        }
        PlanServiceError::ActorSessionInvalid | PlanServiceError::ActorPermissionRequired => {
            tracing::error!("actor authorization outcome escaped the assignment handler");
            error::internal()
        }
        PlanServiceError::ManagementActor(error_value) => {
            tracing::error!(error = %error_value, "management actor outcome escaped the plan handler");
            error::internal()
        }
        PlanServiceError::Audit(error_value) => {
            tracing::error!(error = %error_value, "plan mutation rolled back because audit failed");
            error::service_unavailable(
                "audit_unavailable",
                "the operation was rolled back because its audit record could not be written; retry later",
            )
        }
        PlanServiceError::Database(database_error) => {
            tracing::error!(error = %database_error, "plan database operation failed");
            error::internal()
        }
    }
}
