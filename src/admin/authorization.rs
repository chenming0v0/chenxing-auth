use axum::http::HeaderMap;

use super::{domain::AdminPermission, handlers::is_admin_request};
use crate::{
    error,
    state::AppState,
    users::domain::UserId,
    users::ui_auth::{current_user, user_csrf_valid},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminActor {
    User(UserId),
    SystemToken,
}

impl AdminActor {
    pub const fn actor_type(self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::SystemToken => "system_token",
        }
    }

    pub fn user_id(self) -> Option<UserId> {
        match self {
            Self::User(user_id) => Some(user_id),
            Self::SystemToken => None,
        }
    }

    pub fn audit_fields(self) -> (&'static str, Option<String>) {
        (self.actor_type(), self.user_id().map(|id| id.to_string()))
    }
}

pub async fn current_admin_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: AdminPermission,
) -> Result<AdminActor, axum::response::Response> {
    if is_admin_request(state, headers) {
        return Ok(AdminActor::SystemToken);
    }
    let context = current_user(state, headers).await?;
    if !context.role.allows(permission) {
        return Err(error::unauthorized(
            "admin_forbidden",
            "administrator permission is insufficient",
        ));
    }
    Ok(AdminActor::User(context.user_id))
}

pub async fn current_admin_mutation(
    state: &AppState,
    headers: &HeaderMap,
    permission: AdminPermission,
) -> Result<AdminActor, axum::response::Response> {
    if is_admin_request(state, headers) {
        return Ok(AdminActor::SystemToken);
    }
    let context = current_user(state, headers).await?;
    if !user_csrf_valid(headers, &context.session) {
        return Err(error::bad_request("csrf_invalid", "CSRF token is invalid"));
    }
    if !context.role.allows(permission) {
        return Err(error::unauthorized(
            "admin_forbidden",
            "administrator permission is insufficient",
        ));
    }
    Ok(AdminActor::User(context.user_id))
}
