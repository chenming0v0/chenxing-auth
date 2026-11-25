use axum::{
    Router,
    middleware::{from_fn, from_fn_with_state},
    routing::get,
};
use std::time::Duration;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

mod app_link_lookup;
mod assetlinks;
mod discovery;
pub mod extract;
mod health;
mod issuer_gate;
mod navigation;
mod request_context;
mod response_middleware;
mod routes;
mod security_headers;
mod static_files;
mod timeout;

use navigation::bootstrap_navigation_guard;
pub(crate) use request_context::{source_ip, user_agent};
use response_middleware::{apply_security_headers, map_api_parameter_rejection, request_span};

pub fn router(state: AppState) -> Router {
    let request_timeout = Duration::from_secs(state.config.request_timeout_seconds);
    let state_for_middleware = state.clone();

    let static_service = static_files::static_service(&state.web_dist);
    // Issuer 门禁在 next.run 之前 await load_raw。超时必须作为更外层的
    // route_layer 包住门禁，否则 AwaitingIssuer 期间卡住的库查询会绕过预算。
    let application = timeout::wrap_with_request_timeout(
        routes::register(Router::new()).route_layer(from_fn_with_state(
            state_for_middleware.clone(),
            issuer_gate::require_issuer,
        )),
        request_timeout,
    );
    // Bootstrap / issuer 必须在 Issuer 未就绪时仍可访问；鉴权仍由各自 extractor 执行。
    // 超时与 application router 共用同一层，health 有自己的 2 秒预算，不能套进来。
    let system_api = timeout::wrap_with_request_timeout(
        Router::new()
            // Retired protocol has no issuer/auth/body dependencies and never redirects.
            .route(
                "/api/v1/auth/chenxing/exchange",
                axum::routing::post(crate::resource_services::exchange::retired),
            )
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
            // Android App Links：声明文件和按数字 ID 查包名都不经 Issuer 门禁。
            .route("/.well-known/assetlinks.json", get(assetlinks::assetlinks))
            .route(
                "/api/v1/oauth/app-links/{numeric_app_id}",
                get(app_link_lookup::lookup_app_link),
            ),
        request_timeout,
    );
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
        .layer(from_fn(map_api_parameter_rejection))
        .layer(from_fn(timeout::map_request_timeout_by_path))
        .layer(from_fn(
            crate::resource_services::exchange::response_boundary,
        ))
        .layer(from_fn_with_state(
            state_for_middleware.clone(),
            bootstrap_navigation_guard,
        ))
        .layer(from_fn_with_state(
            state_for_middleware,
            apply_security_headers,
        ))
}
