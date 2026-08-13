use axum::{
    Json,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{api::extract::SessionRead, error, state::AppState};

const DEFAULT_PAGE: i64 = 1;
const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE_SIZE: i64 = 100;

#[derive(Debug, Deserialize)]
pub struct SecurityEventsQuery {
    page: Option<String>,
    page_size: Option<String>,
}

#[derive(Debug, Serialize)]
struct Paged<T> {
    items: Vec<T>,
    page: i64,
    page_size: i64,
    total: i64,
}

pub async fn list_security_events(
    State(state): State<AppState>,
    session: SessionRead,
    query: Result<Query<SecurityEventsQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(_) => return invalid_pagination(),
    };
    let Some((page, page_size, offset)) = query.bounds() else {
        return invalid_pagination();
    };
    match state
        .audit
        .query_security_events(session.user_id, page_size, offset)
        .await
    {
        Ok((items, total)) => (
            StatusCode::OK,
            Json(Paged {
                items,
                page,
                page_size,
                total,
            }),
        )
            .into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to query user security events");
            error::internal()
        }
    }
}

impl SecurityEventsQuery {
    fn bounds(&self) -> Option<(i64, i64, i64)> {
        let page = parse_positive_integer(self.page.as_deref(), DEFAULT_PAGE)?;
        let page_size = parse_positive_integer(self.page_size.as_deref(), DEFAULT_PAGE_SIZE)?;
        if page < 1 || !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return None;
        }
        let offset = page.checked_sub(1)?.checked_mul(page_size)?;
        Some((page, page_size, offset))
    }
}

fn parse_positive_integer(value: Option<&str>, default: i64) -> Option<i64> {
    match value {
        Some(value) if !value.is_empty() => value.parse().ok(),
        Some(_) => None,
        None => Some(default),
    }
}

fn invalid_pagination() -> Response {
    error::bad_request(
        "invalid_pagination",
        "page must be positive and page_size must be between 1 and 100",
    )
}

/// `GET /api/v1/auth/security-events/{id}`：单个安全事件详情（Issue #308）。
///
/// 鉴权与列表接口同一尺度（普通 Session Cookie）。事件不存在或不属于当前用户时
/// 一律 404，不区分「查不到」与「不是你的」，避免把事件 id 变成枚举探测面。
/// 详情字段全部来自白名单（分级映射 + metadata 请求上下文提取），不透出 metadata
/// 原文、令牌、密钥或内部资源标识。
pub async fn get_security_event(
    State(state): State<AppState>,
    session: SessionRead,
    Path(event_id): Path<i64>,
) -> Response {
    // 非正 id 不可能对应任何审计行，与「查不到」同响应。
    if event_id < 1 {
        return security_event_not_found();
    }
    match state
        .audit
        .query_security_event(session.user_id, event_id)
        .await
    {
        Ok(Some(event)) => (StatusCode::OK, Json(event)).into_response(),
        Ok(None) => security_event_not_found(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to query user security event detail");
            error::internal()
        }
    }
}

fn security_event_not_found() -> Response {
    error::not_found("security_event_not_found", "security event is not found")
}
