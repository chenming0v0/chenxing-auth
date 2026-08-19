use axum::{
    Router,
    extract::{Request as AxumRequest, State},
    http::{HeaderMap, Request, header::ACCEPT},
    middleware::{Next, from_fn, from_fn_with_state},
    response::{IntoResponse, Redirect, Response},
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
            state_for_middleware.clone(),
            bootstrap_navigation_guard,
        ))
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

/// Keep the first-deployment redirect in the HTTP navigation boundary instead of making the
/// production SPA probe an intentionally hidden `404` API route on every mount.
async fn bootstrap_navigation_guard(
    State(state): State<AppState>,
    request: AxumRequest,
    next: Next,
) -> Response {
    if !is_document_navigation(&request) {
        return next.run(request).await;
    }
    let path = request.uri().path();
    if !is_spa_navigation_path(path) {
        return next.run(request).await;
    }

    let initialized = match state.users.owner_initialized().await {
        Ok(initialized) => initialized,
        Err(error_value) => {
            tracing::warn!(
                error = %error_value,
                event = "bootstrap.navigation_state_unavailable",
                "continuing with the SPA shell because bootstrap navigation state is unavailable"
            );
            return next.run(request).await;
        }
    };

    if let Some(target) = navigation_target(path, initialized) {
        return Redirect::temporary(target).into_response();
    }
    next.run(request).await
}

fn is_document_navigation(request: &AxumRequest) -> bool {
    if !matches!(
        request.method(),
        &axum::http::Method::GET | &axum::http::Method::HEAD
    ) {
        return false;
    }
    if !is_spa_navigation_path(request.uri().path()) {
        return false;
    }
    let accepts_html = request
        .headers()
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|item| item.trim().starts_with("text/html"))
        });
    if !accepts_html {
        return false;
    }
    request
        .headers()
        .get("sec-fetch-dest")
        .is_none_or(|value| value.as_bytes() == b"document")
}

fn navigation_target(path: &str, initialized: bool) -> Option<&'static str> {
    if !is_spa_navigation_path(path) {
        return None;
    }
    if initialized {
        (path == "/bootstrap").then_some("/login")
    } else {
        (path != "/bootstrap").then_some("/bootstrap")
    }
}

fn is_spa_navigation_path(path: &str) -> bool {
    if path.contains('%')
        || path.starts_with("/assets/")
        || path == "/api"
        || path.starts_with("/api/")
        || path == "/auth/external"
        || path.starts_with("/auth/external/")
        || path == "/health"
        || path.starts_with("/health/")
        || path == "/.well-known"
        || path.starts_with("/.well-known/")
        || path.split('/').any(|segment| segment.starts_with('.'))
        || has_file_extension(path)
    {
        return false;
    }
    if path == "/oauth" || path.starts_with("/oauth/") {
        return matches!(
            path,
            "/oauth/account" | "/oauth/consent" | "/oauth/redirect"
        );
    }
    true
}

fn has_file_extension(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|segment| {
        segment
            .rsplit_once('.')
            .is_some_and(|(_, extension)| !extension.is_empty())
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};

    fn document_request(path: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(path)
            .header("accept", "text/html,application/xhtml+xml")
            .header("sec-fetch-dest", "document")
            .body(Body::empty())
            .expect("document request")
    }

    #[test]
    fn document_navigation_requires_html_accept_and_document_fetch_metadata() {
        assert!(is_document_navigation(&document_request("/login")));

        let api_request = Request::builder()
            .method("GET")
            .uri("/api/v1/auth/me")
            .header("accept", "application/json")
            .body(Body::empty())
            .expect("api request");
        assert!(!is_document_navigation(&api_request));

        let asset_request = document_request("/assets/index-ABC12345.js");
        assert!(!is_document_navigation(&asset_request));

        let non_document_fetch = Request::builder()
            .method("GET")
            .uri("/login")
            .header("accept", "text/html")
            .header("sec-fetch-dest", "empty")
            .body(Body::empty())
            .expect("fetch request");
        assert!(!is_document_navigation(&non_document_fetch));
    }

    #[test]
    fn bootstrap_navigation_target_preserves_first_light_and_ready_routes() {
        assert_eq!(navigation_target("/login", false), Some("/bootstrap"));
        assert_eq!(navigation_target("/console", false), Some("/bootstrap"));
        assert_eq!(navigation_target("/bootstrap", false), None);
        assert_eq!(navigation_target("/bootstrap", true), Some("/login"));
        assert_eq!(navigation_target("/login", true), None);
        assert_eq!(navigation_target("/api/v1/auth/me", false), None);
        assert_eq!(navigation_target("/assets/index-ABC12345.js", false), None);
        assert_eq!(navigation_target("/oauth/authorize", false), None);
        assert_eq!(
            navigation_target("/oauth/account", false),
            Some("/bootstrap")
        );
    }
}
