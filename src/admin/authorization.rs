use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

use super::{
    domain::{AdminId, AdminPermission},
    handlers::is_admin_request,
    session::{ADMIN_CSRF_COOKIE, ADMIN_SESSION_COOKIE},
};
use crate::{error, sessions::cookies, state::AppState};

pub async fn current_admin_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: AdminPermission,
) -> Result<AdminId, axum::response::Response> {
    let Some((admin_id, role, status)) = load_admin(state, headers).await? else {
        return Err(error::unauthorized(
            "admin_required",
            "administrator authorization is required",
        ));
    };
    if status != "active" || !role.allows(permission) {
        return Err(error::unauthorized(
            "admin_forbidden",
            "administrator permission is insufficient",
        ));
    }
    Ok(admin_id)
}

pub async fn current_admin_mutation(
    state: &AppState,
    headers: &HeaderMap,
    permission: AdminPermission,
) -> Result<AdminId, axum::response::Response> {
    let Some(session_id) = admin_session_id(headers) else {
        if is_admin_request(state, headers) {
            return Ok(0);
        }
        return Err(error::unauthorized(
            "admin_required",
            "administrator authorization is required",
        ));
    };
    let Some(session) = state
        .admin_sessions
        .find(session_id)
        .await
        .map_err(|_| error::internal())?
    else {
        return Err(error::unauthorized(
            "invalid_session",
            "administrator session is invalid",
        ));
    };
    if !admin_csrf_valid(headers, &session.csrf_token) {
        return Err(error::bad_request("csrf_invalid", "CSRF token is invalid"));
    }
    let Some((admin_id, role, status)) = load_admin(state, headers).await? else {
        return Err(error::unauthorized(
            "invalid_session",
            "administrator account is invalid",
        ));
    };
    if status != "active" || !role.allows(permission) {
        return Err(error::unauthorized(
            "admin_forbidden",
            "administrator permission is insufficient",
        ));
    }
    Ok(admin_id)
}

async fn load_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<(AdminId, super::domain::AdminRole, String)>, axum::response::Response> {
    if is_admin_request(state, headers) {
        return Ok(Some((
            0,
            super::domain::AdminRole::Owner,
            "active".to_owned(),
        )));
    }
    let Some(session_id) = admin_session_id(headers) else {
        return Ok(None);
    };
    let Some(session) = state
        .admin_sessions
        .find(session_id)
        .await
        .map_err(|_| error::internal())?
    else {
        return Ok(None);
    };
    let Some((admin_id, _, role, status)) = state
        .admins
        .find(session.admin_id)
        .await
        .map_err(|_| error::internal())?
    else {
        return Ok(None);
    };
    Ok(Some((admin_id, role, status)))
}

pub(crate) fn admin_session_id(headers: &HeaderMap) -> Option<uuid::Uuid> {
    cookies::cookie_value_by_name(headers, ADMIN_SESSION_COOKIE)
        .and_then(|value| uuid::Uuid::parse_str(&value).ok())
}

pub fn admin_csrf_valid(headers: &HeaderMap, expected: &str) -> bool {
    let Some(header_value) = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    cookies::cookie_value_by_name(headers, ADMIN_CSRF_COOKIE).is_some_and(|value| {
        value.len() == expected.len()
            && header_value.len() == expected.len()
            && value.as_bytes().ct_eq(expected.as_bytes()).into()
            && header_value.as_bytes().ct_eq(expected.as_bytes()).into()
    })
}
