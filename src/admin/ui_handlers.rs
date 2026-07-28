use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    authorization::current_admin_permission,
    domain::{AdminId, AdminPermission, AdminRole},
    handlers::is_admin_request,
    session::ADMIN_SESSION_COOKIE,
};
use crate::{error, sessions::cookies, state::AppState};

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
    admin_id: Option<AdminId>,
    username: Option<String>,
    role: &'static str,
    permissions: Vec<&'static str>,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct OverviewResponse {
    users: usize,
    oauth_clients: usize,
    administrators: usize,
    audit_events: usize,
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
                admin_id: None,
                username: None,
                role: AdminRole::Owner.as_str(),
                permissions: permissions(AdminRole::Owner),
                status: "active",
            }),
        )
            .into_response();
    }
    let Some(session_id) = cookies::cookie_value_by_name(&headers, ADMIN_SESSION_COOKIE)
        .and_then(|value| Uuid::parse_str(&value).ok())
    else {
        return error::unauthorized("admin_required", "administrator authorization is required");
    };
    let Some(session) = state.admin_sessions.find(session_id).await.ok().flatten() else {
        return error::unauthorized("invalid_session", "administrator session is invalid");
    };
    let Some((admin_id, username, role, status)) =
        state.admins.find(session.admin_id).await.ok().flatten()
    else {
        return error::unauthorized("invalid_session", "administrator account is invalid");
    };
    if status != "active" {
        return error::unauthorized("admin_forbidden", "administrator account is disabled");
    }
    (
        axum::http::StatusCode::OK,
        Json(AdminMeResponse {
            admin_id: Some(admin_id),
            username: Some(username),
            role: role.as_str(),
            permissions: permissions(role),
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
    let users = match state.users.list().await {
        Ok(value) => value.len(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to count users for admin overview");
            return error::internal();
        }
    };
    let oauth_clients = match state.clients.list().await {
        Ok(value) => value.len(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to count clients for admin overview");
            return error::internal();
        }
    };
    let administrators = match state.admins.list().await {
        Ok(value) => value.len(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to count administrators for admin overview");
            return error::internal();
        }
    };
    let audit_events = match state.audit.count().await {
        Ok(value) => value as usize,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to count audit events for admin overview");
            return error::internal();
        }
    };
    (
        axum::http::StatusCode::OK,
        Json(OverviewResponse {
            users,
            oauth_clients,
            administrators,
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
    let mut users = match state.users.list().await {
        Ok(value) => value,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to query users");
            return error::internal();
        }
    };
    users.retain(|user| {
        query
            .status
            .as_deref()
            .is_none_or(|status| status == user.status)
            && query.search.as_deref().is_none_or(|search| {
                let search = search.to_ascii_lowercase();
                user.username.to_ascii_lowercase().contains(&search)
                    || user.email.to_ascii_lowercase().contains(&search)
                    || user
                        .display_name
                        .as_deref()
                        .is_some_and(|name| name.to_ascii_lowercase().contains(&search))
            })
    });
    let total = users.len() as i64;
    let items = users
        .into_iter()
        .skip(offset as usize)
        .take(page_size as usize)
        .map(|user| super::management_handlers::UserSummary {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name: user.display_name,
            status: user.status,
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
    let mut clients = match state.clients.list().await {
        Ok(value) => value,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to query clients");
            return error::internal();
        }
    };
    clients.retain(|client| {
        query
            .status
            .as_deref()
            .is_none_or(|status| status == client.status)
            && query.search.as_deref().is_none_or(|search| {
                client.client_id.contains(search) || client.client_name.contains(search)
            })
    });
    let total = clients.len() as i64;
    let items = clients
        .into_iter()
        .skip(offset as usize)
        .take(page_size as usize)
        .collect::<Vec<_>>();
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
    let (events, total) = match state
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
    let items = events;
    page_response(items, page, page_size, total)
}

fn bounds(query: &PageQuery) -> Option<(i64, i64, i64)> {
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(20);
    if page < 1 || !(1..=100).contains(&page_size) {
        return None;
    }
    let offset = (page - 1).checked_mul(page_size)?;
    Some((page, page_size, offset))
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
    ]
    .into_iter()
    .filter_map(|(permission, name)| role.allows(permission).then_some(name))
    .collect()
}
