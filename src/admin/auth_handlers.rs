use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::{fmt, net::SocketAddr};

use super::{
    bootstrap_guard::{
        enforce_bootstrap_attempt_limit, hidden_bootstrap_status, record_bootstrap_denial,
    },
    domain::AdminPermission,
    user_creation::user_creation_error_response,
};
use crate::{
    api::extract::AdminWrite,
    audit::AuditEvent,
    error,
    state::AppState,
    users::domain::{RegistrationInput, UserRole},
};

#[derive(Deserialize)]
pub struct BootstrapAdmin {
    pub username: String,
    pub email: String,
    pub password: String,
}

impl fmt::Debug for BootstrapAdmin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BootstrapAdmin")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
pub struct CreateAdmin {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: String,
}

impl fmt::Debug for CreateAdmin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateAdmin")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("role", &self.role)
            .finish()
    }
}

#[derive(Debug, serde::Serialize)]
pub struct BootstrapStatusResponse {
    pub initialized: bool,
}

/// 初始化状态探测。
///
/// 未初始化时如实返回 `initialized: false`——初始化页面必须能判断是否显示，这是
/// Owner 引导例外的一部分。已初始化后返回与未注册路由一致的 404，不再向匿名调用者
/// 确认「这是一台已初始化的辰星实例」。详见 [`super::bootstrap_guard`]。
pub async fn bootstrap_status(State(state): State<AppState>) -> Response {
    match state.users.owner_initialized().await {
        Ok(false) => (
            StatusCode::OK,
            Json(BootstrapStatusResponse { initialized: false }),
        )
            .into_response(),
        Ok(true) => hidden_bootstrap_status(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to query owner bootstrap status");
            error::internal()
        }
    }
}

pub async fn bootstrap_admin(
    State(state): State<AppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<BootstrapAdmin>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    // 限流先于 `bootstrap_owner`：后者要跑 Argon2（19 MiB 内存），匿名请求不能
    // 无配额地触发它，否则限流面本身变成内存放大的 DoS 面。
    if let Some(response) = enforce_bootstrap_attempt_limit(&state, source_ip.as_deref()).await {
        return response;
    }
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
                    // 源 IP 让「谁抢到了 Owner」在事后可追溯；键在审计脱敏白名单内。
                    serde_json::json!({"role": "owner", "source_ip": source_ip}),
                ))
                .await;
            (StatusCode::CREATED, Json(serde_json::json!({
                "id": profile.id, "username": profile.username, "email": profile.email, "role": "owner"
            }))).into_response()
        }
        Ok(crate::users::service::BootstrapOwnerResult::AlreadyConfigured) => {
            // 已初始化实例上的引导尝试是探测行为，必须留痕：状态端点关闭后 POST
            // 成为唯一的探测手段，它的每次尝试都要可检索。
            record_bootstrap_denial(&state, source_ip.as_deref(), "already_completed").await;
            error::conflict(
                "bootstrap_already_completed",
                "owner bootstrap is already configured",
            )
        }
        Ok(crate::users::service::BootstrapOwnerResult::RequiresEmptyDatabase) => {
            record_bootstrap_denial(&state, source_ip.as_deref(), "requires_empty_database").await;
            error::conflict(
                "owner_bootstrap_requires_empty_database",
                "owner bootstrap requires an empty users table; clear the database before retrying",
            )
        }
        // 引导专属的两个冲突（already_completed / requires_empty_database）是
        // `BootstrapOwnerResult` 的成功分支，留在上面；其余失败与另外两个创建端点同构。
        Err(error_value) => user_creation_error_response(error_value),
    }
}

pub async fn create_admin(
    State(state): State<AppState>,
    admin: AdminWrite,
    Json(input): Json<CreateAdmin>,
) -> Response {
    let actor = match admin.authorize(&state, AdminPermission::ManageRoles).await {
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
