use axum::{
    Router,
    extract::{Request as AxumRequest, State},
    http::{HeaderMap, Request},
    middleware::{Next, from_fn, from_fn_with_state},
    response::Response,
    routing::get,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower_http::trace::TraceLayer;

use crate::{config::TrustedProxies, state::AppState};

mod discovery;
pub mod extract;
mod health;
mod issuer_gate;
mod routes;
mod security_headers;
mod static_files;
mod timeout;

/// 请求 query 可能包含 OAuth 凭据和状态值，不能进入 HTTP trace span。
fn request_span<B>(request: &Request<B>) -> tracing::Span {
    tracing::debug_span!(
        "request",
        method = %request.method(),
        uri = %request.uri().path(),
    )
}

pub fn router(state: AppState) -> Router {
    let request_timeout = Duration::from_secs(state.config.request_timeout_seconds);
    let state_for_middleware = state.clone();

    let static_service = static_files::static_service(&state.web_dist);
    let application = routes::register(Router::new(), request_timeout).route_layer(
        from_fn_with_state(state_for_middleware.clone(), issuer_gate::require_issuer),
    );
    // Bootstrap / issuer 必须在 Issuer 未就绪时仍可访问；鉴权仍由各自 extractor 执行。
    // 超时与 application router 共用同一层，health 有自己的 2 秒预算，不能套进来。
    let system_api = Router::new()
        .route("/api/v1/admin/bootstrap/status", get(health::system_status))
        // 匿名 status 只回答 initialized/uninitialized，不暴露 Issuer 收敛状态。
        .route(
            "/api/v1/admin/bootstrap",
            axum::routing::post(crate::admin::auth_handlers::bootstrap_admin),
        )
        .route(
            "/api/v1/admin/settings/issuer",
            get(crate::admin::issuer_settings_handlers::get_issuer_setting)
                .put(crate::admin::issuer_settings_handlers::update_issuer_setting),
        )
        .route_layer(timeout::request_timeout_layer(request_timeout));
    let health = Router::new()
        .route("/health", get(health::health))
        .route("/health/live", get(health::health_live))
        .route("/health/ready", get(health::health_ready));
    system_api
        .merge(health)
        .merge(application)
        // fallback 只处理未匹配路径，协议和健康路由不会被静态服务抢走。
        .fallback_service(static_service)
        .with_state(state)
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
        .layer(from_fn(timeout::map_request_timeout_by_path))
        .layer(from_fn_with_state(
            state_for_middleware,
            apply_security_headers,
        ))
}

async fn apply_security_headers(
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
    security_headers::apply(response, hsts_enabled).await
}

/// 从请求对端地址和头部解析真实客户端 IP。
///
/// **安全规则**（#111）：
/// - 未配置可信代理或对端不可信 → 用对端地址，忽略 XFF（防伪造）
/// - 对端可信且有 XFF → 先把所有 XFF 头部行按线序合并成一条链路（#269），
///   再从右往左扫描，第一个不可信的 IP 是客户端
///
/// 此函数收敛了项目中所有的源 IP 解析逻辑。注册、OAuth `/token`、TOTP、Passkey
/// 和登录端点都调用它。未配置 `trusted_proxies` 时启动阶段已告警。
pub(crate) fn source_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &TrustedProxies,
) -> Option<String> {
    trusted_proxies.resolve_client_ip(peer, headers)
}

/// 提取请求 User-Agent，用于安全日志的请求上下文（Issue #308）。
///
/// UA 是客户端可伪造的任意长度头部，不能整段进审计：截断到 512 字符，非 UTF-8
/// 或无 UA 的请求返回 `None`。安全日志里它只与源 IP 一起出现，供用户核对
/// 「谁在什么时候用什么设备访问了我的账户」。
pub(crate) fn user_agent(headers: &HeaderMap) -> Option<String> {
    const MAX_USER_AGENT_CHARS: usize = 512;
    let value = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())?;
    Some(match value.char_indices().nth(MAX_USER_AGENT_CHARS) {
        Some((index, _)) => value[..index].to_owned(),
        None => value.to_owned(),
    })
}
