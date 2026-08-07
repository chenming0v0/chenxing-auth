use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use super::{
    authorization::current_admin_mutation, domain::AdminPermission,
    user_creation::user_creation_error_response,
};
use crate::{
    audit::AuditEvent,
    error,
    state::AppState,
    users::domain::{RegistrationInput, UserRole},
};

#[derive(Debug, Deserialize)]
pub struct BootstrapAdmin {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateAdmin {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, serde::Serialize)]
pub struct BootstrapStatusResponse {
    pub initialized: bool,
}

pub async fn bootstrap_status(State(state): State<AppState>) -> Response {
    match state.users.owner_initialized().await {
        Ok(initialized) => (
            StatusCode::OK,
            Json(BootstrapStatusResponse { initialized }),
        )
            .into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to query owner bootstrap status");
            error::internal()
        }
    }
}

pub async fn bootstrap_admin(
    State(state): State<AppState>,
    Json(input): Json<BootstrapAdmin>,
) -> Response {
    let registration = RegistrationInput {
        username: input.username,
        email: input.email,
        password: input.password,
        display_name: None,
    };
    match state.users.bootstrap_owner(registration).await {
        Ok(crate::users::service::BootstrapOwnerResult::Created(profile)) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "bootstrap".to_owned(),
                    None,
                    "owner_bootstrap".to_owned(),
                    "user".to_owned(),
                    Some(profile.id.to_string()),
                    serde_json::json!({"role": "owner"}),
                ))
                .await;
            (StatusCode::CREATED, Json(serde_json::json!({
                "id": profile.id, "username": profile.username, "email": profile.email, "role": "owner"
            }))).into_response()
        }
        Ok(crate::users::service::BootstrapOwnerResult::AlreadyConfigured) => error::conflict(
            "bootstrap_already_completed",
            "owner bootstrap is already configured",
        ),
        Ok(crate::users::service::BootstrapOwnerResult::RequiresEmptyDatabase) => error::conflict(
            "owner_bootstrap_requires_empty_database",
            "owner bootstrap requires an empty users table; clear the database before retrying",
        ),
        // 引导专属的两个冲突（already_completed / requires_empty_database）是
        // `BootstrapOwnerResult` 的成功分支，留在上面；其余失败与另外两个创建端点同构。
        Err(error_value) => user_creation_error_response(error_value),
    }
}

pub async fn create_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateAdmin>,
) -> Response {
    let actor = match current_admin_mutation(&state, &headers, AdminPermission::ManageRoles).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let Some(role) = UserRole::parse(&input.role)
        .filter(|role| matches!(role, UserRole::Admin | UserRole::Owner))
    else {
        return error::bad_request(
            "invalid_role",
            "privileged user role must be admin or owner",
        );
    };
    let registration = RegistrationInput {
        username: input.username,
        email: input.email,
        password: input.password,
        display_name: None,
    };
    match state.users.create_privileged(registration, role).await {
        Ok(id) => {
            let (actor_type, actor_id) = actor.audit_fields();
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    actor_type.to_owned(),
                    actor_id,
                    "user_create".to_owned(),
                    "user".to_owned(),
                    Some(id.to_string()),
                    serde_json::json!({"role": role.as_str()}),
                ))
                .await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({"id": id, "role": role.as_str()})),
            )
                .into_response()
        }
        Err(error_value) => user_creation_error_response(error_value),
    }
}
