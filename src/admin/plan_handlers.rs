use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::{
    authorization::{current_admin_mutation, current_admin_permission},
    domain::AdminPermission,
};
use crate::{
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

pub async fn list_plans(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageSettings).await
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
    headers: HeaderMap,
    Json(input): Json<PlanInput>,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageSettings).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    match state.plans.create(input).await {
        Ok(plan) => {
            record_plan_event(&state, actor, "plan_create", &plan.code).await;
            (StatusCode::CREATED, Json(plan_response(plan, 0))).into_response()
        }
        Err(error_value) => plan_error_response(error_value),
    }
}

pub async fn update_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<PlanInput>,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageSettings).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    match state.plans.update(id, input).await {
        Ok(plan) => {
            record_plan_event(&state, actor, "plan_update", &plan.code).await;
            (StatusCode::OK, Json(plan_response(plan, 0))).into_response()
        }
        Err(error_value) => plan_error_response(error_value),
    }
}

pub async fn archive_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    change_plan_status(state, headers, id, "plan_archive", "archive").await
}

pub async fn restore_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    change_plan_status(state, headers, id, "plan_restore", "restore").await
}

async fn change_plan_status(
    state: AppState,
    headers: HeaderMap,
    id: i64,
    action: &'static str,
    operation: &'static str,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageSettings).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let result = if operation == "archive" {
        state.plans.archive(id).await
    } else {
        state.plans.restore(id).await
    };
    match result {
        Ok(()) => {
            record_plan_event(&state, actor, action, &id.to_string()).await;
            StatusCode::NO_CONTENT.into_response()
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

pub async fn assign_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<UserId>,
    Json(input): Json<AssignPlanInput>,
) -> Response {
    let actor =
        match current_admin_mutation(&state, &headers, AdminPermission::ManageSettings).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let expires_at = match parse_expiry(input.expires_at) {
        Ok(expires_at) => expires_at,
        Err(message) => return error::bad_request("invalid_expiration", message),
    };
    match state
        .plans
        .assign_to_user(user_id, input.plan_id, expires_at)
        .await
    {
        Ok(()) => {
            record_plan_event(&state, actor, "user_plan_assign", &user_id.to_string()).await;
            StatusCode::NO_CONTENT.into_response()
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
        PlanServiceError::DefaultPlanProtected => error::conflict(
            "default_plan_protected",
            "the default plan cannot be archived",
        ),
        PlanServiceError::PlanArchived => error::bad_request(
            "plan_archived",
            "archived plans cannot be assigned to users",
        ),
        PlanServiceError::UserNotFound => error::not_found("user_not_found", "user was not found"),
        PlanServiceError::NoDefaultPlan => {
            tracing::error!("no default plan is configured");
            error::internal()
        }
        PlanServiceError::Database(database_error) => {
            tracing::error!(error = %database_error, "plan database operation failed");
            error::internal()
        }
    }
}

async fn record_plan_event(
    state: &AppState,
    actor: super::authorization::AdminActor,
    action: &str,
    resource_id: &str,
) {
    let (actor_type, actor_id) = actor.audit_fields();
    state
        .audit
        .record(AuditEvent::new(
            actor_type.to_owned(),
            actor_id,
            action.to_owned(),
            "plan".to_owned(),
            Some(resource_id.to_owned()),
            serde_json::json!({"result": "success"}),
        ))
        .await;
}
