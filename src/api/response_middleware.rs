//! 响应边界：参数错误信封、安全头以及不含 query 的请求追踪。

use axum::{
    extract::{Request as AxumRequest, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::state::AppState;

/// 请求 query 可能包含 OAuth 凭据和状态值，不能进入 HTTP trace span。
pub(super) fn request_span<B>(request: &Request<B>) -> tracing::Span {
    tracing::debug_span!(
        "request",
        method = %request.method(),
        uri = %request.uri().path(),
    )
}

pub(super) async fn map_api_parameter_rejection(request: AxumRequest, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let response = next.run(request).await;
    let is_parameter_rejection = matches!(
        response.status(),
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
    ) && response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| !value.starts_with("application/json"));
    if is_api && is_parameter_rejection {
        return crate::error::parameter_rejection(response.status());
    }
    response
}

pub(super) async fn apply_security_headers(
    State(state): State<AppState>,
    request: AxumRequest,
    next: Next,
) -> Response {
    let response = next.run(request).await;
    let request_snapshot = response
        .extensions()
        .get::<Arc<crate::settings::IssuerSnapshot>>()
        .cloned();
    let hsts_enabled = request_snapshot
        .or_else(|| state.issuer.current())
        .is_some_and(|snapshot| snapshot.issuer().is_https());
    super::security_headers::apply(response, hsts_enabled).await
}
