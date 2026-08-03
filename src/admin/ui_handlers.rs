use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    authorization::current_admin_permission,
    domain::{AdminPermission, AdminRole},
    handlers::is_admin_request,
};
use crate::{
    error,
    state::AppState,
    users::{domain::UserRole, ui_auth::current_user},
};

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub search: Option<String>,
    pub status: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
}
#[derive(Debug, Serialize)]
struct AdminMeResponse {
    user_id: Option<crate::users::domain::UserId>,
    username: Option<String>,
    role: &'static str,
    permissions: Vec<&'static str>,
    status: &'static str,
}
#[derive(Debug, Serialize)]
struct OverviewResponse {
    users: i64,
    oauth_clients: i64,
    administrators: i64,
    audit_events: i64,
}
#[derive(Debug, Serialize)]
struct PageResponse<T> {
    items: Vec<T>,
    page: i64,
    page_size: i64,
    total: i64,
}

pub async fn admin_me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if is_admin_request(&state, &headers) {
        return (
            axum::http::StatusCode::OK,
            Json(AdminMeResponse {
                user_id: None,
                username: None,
                role: "owner",
                permissions: permissions(AdminRole::Owner),
                status: "active",
            }),
        )
            .into_response();
    }
    let Ok(context) = current_user(&state, &headers).await else {
        return error::unauthorized("admin_required", "administrator authorization is required");
    };
    if !matches!(context.role, UserRole::Admin | UserRole::Owner) {
        return error::forbidden("admin_forbidden", "administrator authorization is required");
    }
    let Some(profile) = state
        .users
        .find_profile(context.user_id)
        .await
        .ok()
        .flatten()
    else {
        return error::unauthorized("invalid_session", "user account is invalid");
    };
    (
        axum::http::StatusCode::OK,
        Json(AdminMeResponse {
            user_id: Some(profile.id),
            username: Some(profile.username),
            role: context.role.as_str(),
            permissions: permissions(context.role),
            status: "active",
        }),
    )
        .into_response()
}

pub async fn admin_overview(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageClients).await
    {
        return response;
    }
    let user_counts = match state.users.counts().await {
        Ok(value) => value,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to count users");
            return error::internal();
        }
    };
    let oauth_clients = match state.clients.count().await {
        Ok(value) => value,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to count clients");
            return error::internal();
        }
    };
    let audit_events = match state.audit.count().await {
        Ok(value) => value,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to count audit events");
            return error::internal();
        }
    };
    (
        axum::http::StatusCode::OK,
        Json(OverviewResponse {
            users: user_counts.total,
            oauth_clients,
            administrators: user_counts.administrators,
            audit_events,
        }),
    )
        .into_response()
}

pub async fn query_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageUsers).await
    {
        return response;
    }
    let Some((page, page_size, offset)) = bounds(&query) else {
        return error::bad_request(
            "invalid_pagination",
            "page must be positive and page_size must be between 1 and 100",
        );
    };
    let (users, total) = match state
        .users
        .query(
            query.search.as_deref(),
            query.status.as_deref(),
            page_size,
            offset,
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to query users");
            return error::internal();
        }
    };
    let items = users
        .into_iter()
        .map(|user| super::management_handlers::UserSummary {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name: user.display_name,
            status: user.status,
            role: user.role,
            created_at: user.created_at,
        })
        .collect();
    page_response(items, page, page_size, total)
}

pub async fn query_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageClients).await
    {
        return response;
    }
    let Some((page, page_size, offset)) = bounds(&query) else {
        return error::bad_request(
            "invalid_pagination",
            "page must be positive and page_size must be between 1 and 100",
        );
    };
    let (clients, total) = match state
        .clients
        .query(
            query.search.as_deref(),
            query.status.as_deref(),
            page_size,
            offset,
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to query clients");
            return error::internal();
        }
    };
    let items = clients;
    page_response(items, page, page_size, total)
}

pub async fn query_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ReadAudit).await
    {
        return response;
    }
    let Some((page, page_size, offset)) = bounds(&query) else {
        return error::bad_request(
            "invalid_pagination",
            "page must be positive and page_size must be between 1 and 100",
        );
    };
    let (items, total) = match state
        .audit
        .query(
            query.action.as_deref(),
            query.resource_type.as_deref(),
            page_size,
            offset,
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to query audit events");
            return error::internal();
        }
    };
    page_response(items, page, page_size, total)
}

fn bounds(query: &PageQuery) -> Option<(i64, i64, i64)> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    Some((page, page_size, (page - 1).checked_mul(page_size)?))
}
fn page_response<T: Serialize>(items: Vec<T>, page: i64, page_size: i64, total: i64) -> Response {
    (
        axum::http::StatusCode::OK,
        Json(PageResponse {
            items,
            page,
            page_size,
            total,
        }),
    )
        .into_response()
}
fn permissions(role: AdminRole) -> Vec<&'static str> {
    [
        (AdminPermission::ManageUsers, "manage_users"),
        (AdminPermission::ManageClients, "manage_clients"),
        (AdminPermission::RotateKeys, "rotate_keys"),
        (AdminPermission::ReadAudit, "read_audit"),
        (AdminPermission::ManageSettings, "manage_settings"),
        (
            AdminPermission::ManageIdentityProviders,
            "manage_identity_providers",
        ),
        (AdminPermission::ManageRoles, "manage_roles"),
    ]
    .into_iter()
    .filter_map(|(permission, name)| role.allows(permission).then_some(name))
    .collect()
}
