//! 管理侧用户创建（Issue #133）与用户创建错误的统一映射。
//!
//! `POST /api/v1/admin/users` 是 `POST /api/v1/admin/admins` 的一般化：后者只能
//! 创建 admin/owner 且状态固定 active，这里允许指定任意角色与初始状态。
//! 三个创建端点（bootstrap / admins / users）此前各自维护一份把
//! `UserServiceError` 翻成 HTTP 的 match 阶梯，任何一处漏掉分支就会把客户端输入
//! 错误翻成 500，因此错误映射收敛到本文件的 [`user_creation_error_response`]。

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::fmt;

use super::domain::AdminPermission;
use crate::{
    api::extract::{AdminWrite, ApiJson},
    error,
    state::AppState,
    users::{
        domain::{RegistrationError, RegistrationInput, UserRole, UserStatus},
        service::UserServiceError,
    },
};

#[derive(Deserialize)]
pub struct CreateUserInput {
    pub username: String,
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
    /// 缺省为 `user`：管理员不显式要求提权时，创建出来的必须是最低权限账号。
    pub role: Option<String>,
    /// 缺省为 `active`。
    pub status: Option<String>,
}

impl fmt::Debug for CreateUserInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateUserInput")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("display_name", &self.display_name)
            .field("role", &self.role)
            .field("status", &self.status)
            .finish()
    }
}

/// 管理员创建用户。
///
/// 权限模型：`ManageUsers` 是基线；请求 admin/owner 角色时把所需权限抬到
/// `ManageRoles`。写路径统一走 [`AdminWrite`]，其 `authorize()` 无条件校验
/// HttpOnly Session Cookie、CSRF Cookie 与 `X-CSRF-Token` 三者绑定。
pub async fn create_user(
    State(state): State<AppState>,
    admin: AdminWrite,
    ApiJson(input): ApiJson<CreateUserInput>,
) -> Response {
    // 角色决定所需权限，必须在守卫之前解析。状态一并在此解析：两个词表都属于
    // 公开 API 契约，先行拒绝非法值不泄露任何信息，也让两个 400 行为一致。
    let role = match input.role.as_deref() {
        Some(value) => match UserRole::parse(value) {
            Some(role) => role,
            None => return error::bad_request("invalid_role", "role is invalid"),
        },
        None => UserRole::User,
    };
    let status = match input.status.as_deref() {
        Some(value) => match UserStatus::parse(value) {
            Some(status) => status,
            None => return error::bad_request("invalid_status", "status is invalid"),
        },
        None => UserStatus::Active,
    };
    // Owner 是唯一拥有 ManageRoles 的角色，而 Owner 覆盖 ManageUsers；
    // 因此提升角色时直接把所需权限抬到 ManageRoles，等价于"额外要求 manage_roles"，
    // 不需要两次会话校验或额外分支。
    let required = if matches!(role, UserRole::Admin | UserRole::Owner) {
        AdminPermission::ManageRoles
    } else {
        AdminPermission::ManageUsers
    };
    let actor = match admin.authorize(&state, required).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if !state.issuer.is_ready() {
        return if state.issuer.is_awaiting_configuration() {
            error::issuer_not_configured()
        } else {
            error::issuer_runtime_invalid()
        };
    }

    let registration = RegistrationInput {
        username: input.username,
        email: input.email,
        password: input.password,
        display_name: input.display_name,
    };
    let (actor_type, actor_id) = actor.audit_fields();
    match state
        .users
        .create_by_admin(registration, role, status, actor_type.to_owned(), actor_id)
        .await
    {
        Ok(user) => (StatusCode::CREATED, Json(user)).into_response(),
        Err(error_value) => user_creation_error_response(error_value),
    }
}

/// 把用户创建失败翻成 HTTP 响应。
///
/// 三个创建端点共用同一份词表，避免"注册端点认得 password_too_long、管理端点
/// 却把它翻成 500"这类分叉。兜底分支必须留在最后并记录日志：新增的
/// `UserServiceError` 变体会走到这里，只暴露 500，不把内部错误文本回给客户端。
pub(crate) fn user_creation_error_response(error: UserServiceError) -> Response {
    match error {
        UserServiceError::Validation(RegistrationError::InvalidEmail) => {
            error::bad_request("invalid_email", "email is invalid")
        }
        UserServiceError::Validation(RegistrationError::InvalidUsername) => {
            error::bad_request("invalid_username", "username is invalid")
        }
        UserServiceError::Validation(RegistrationError::PasswordTooShort) => {
            error::bad_request("password_too_short", "password is too short")
        }
        // #122：超长口令是客户端输入问题，必须落到 400，不能被兜底分支翻成 500。
        UserServiceError::Validation(RegistrationError::PasswordTooLong) => error::bad_request(
            "password_too_long",
            "password must be at most 128 characters",
        ),
        UserServiceError::Validation(RegistrationError::DisplayNameTooLong) => {
            error::bad_request("display_name_too_long", "display name is too long")
        }
        UserServiceError::EmailDomainNotAllowed => {
            error::bad_request("email_domain_not_allowed", "email domain is not allowed")
        }
        UserServiceError::OwnerBootstrapRequired => error::conflict(
            "owner_bootstrap_required",
            "owner bootstrap must be completed before creating privileged users",
        ),
        // Issue #304：同事务审计写入失败已让业务写入回滚，什么都没发生。
        // 503 而不是 500：这是依赖暂时不可用，重试是正确动作，且与
        // `bootstrap_unavailable`（限流器不可用）表达同一类语义。
        UserServiceError::AuditUnavailable => error::service_unavailable(
            "audit_unavailable",
            "the operation was rolled back because its audit record could not be written; retry later",
        ),
        UserServiceError::Database(ref error_value)
            if unique_violation(error_value, "users_username_key") =>
        {
            error::conflict(
                "username_already_registered",
                "username is already registered",
            )
        }
        // 两个约束名都映射到同一个响应（Issue #302）：`users_email_key` 拦的是
        // 展示值完全相同，`users_canonical_email_key` 拦的是书写不同但指向同一个
        // 邮箱（大小写、Unicode/Punycode 等价形态）。对客户端而言都是"这个邮箱
        // 已经被注册了"，区分两者只会泄露"库里已存在的那一行长什么样"。
        UserServiceError::Database(ref error_value)
            if unique_violation(error_value, "users_email_key")
                || unique_violation(error_value, "users_canonical_email_key") =>
        {
            error::conflict("email_already_registered", "email is already registered")
        }
        error_value => {
            tracing::error!(error = %error_value, "failed to create user");
            error::internal()
        }
    }
}

/// 判定数据库错误是否来自指定唯一约束。
///
/// 只看约束名而不解析错误文本：错误文本随 PostgreSQL 版本和 locale 变化，
/// 用它做判定等于把响应码绑在数据库的措辞上。
fn unique_violation(error: &crate::sqlx::Error, constraint: &str) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.constraint())
        .is_some_and(|name| name == constraint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_status_parse_and_as_str_round_trip() {
        for status in [UserStatus::Active, UserStatus::Disabled] {
            assert_eq!(UserStatus::parse(status.as_str()), Some(status));
        }
        // 词表是封闭的：大小写变体和角色名都不得被接受。
        for value in ["", "ACTIVE", "Disabled", "deleted", "user", "owner"] {
            assert!(UserStatus::parse(value).is_none(), "{value}");
        }
    }

    #[test]
    fn validation_errors_map_to_stable_client_error_codes() {
        for (error, status) in [
            (
                UserServiceError::Validation(RegistrationError::InvalidUsername),
                StatusCode::BAD_REQUEST,
            ),
            (
                UserServiceError::Validation(RegistrationError::InvalidEmail),
                StatusCode::BAD_REQUEST,
            ),
            (
                UserServiceError::Validation(RegistrationError::PasswordTooShort),
                StatusCode::BAD_REQUEST,
            ),
            (
                UserServiceError::Validation(RegistrationError::PasswordTooLong),
                StatusCode::BAD_REQUEST,
            ),
            (
                UserServiceError::Validation(RegistrationError::DisplayNameTooLong),
                StatusCode::BAD_REQUEST,
            ),
            (
                UserServiceError::EmailDomainNotAllowed,
                StatusCode::BAD_REQUEST,
            ),
            (
                UserServiceError::OwnerBootstrapRequired,
                StatusCode::CONFLICT,
            ),
            (
                UserServiceError::AuditUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                UserServiceError::PasswordHash,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            assert_eq!(user_creation_error_response(error).status(), status);
        }
    }
}
