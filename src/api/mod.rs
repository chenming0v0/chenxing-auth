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
mod routes;
mod security_headers;
mod static_files;

/// 请求 query 可能包含 OAuth 凭据和状态值，不能进入 HTTP trace span。
fn request_span<B>(request: &Request<B>) -> tracing::Span {
    tracing::debug_span!(
        "request",
        method = %request.method(),
        uri = %request.uri().path(),
    )
}

/// 超时响应按请求路径分流到正确的协议错误格式。
///
/// `tower_http::timeout::TimeoutLayer` 在请求超时时返回空体 504 响应，不携带
/// 任何路径信息。该中间件在调用下游前先记录请求路径，下游返回后若状态码是
/// 504，则按路径选择响应格式：
///
/// - `/oauth/*` 协议端点返回 RFC 6749 `temporarily_unavailable`（503）。
/// - 其余路径返回内部 API 信封 `{code, message}`（504 `request_timeout`）。
///
/// 路径判定在 `error::timeout_response_for_path` 中实现，本中间件只负责把
/// 请求路径传递过去，不做路径解析。
async fn map_request_timeout_by_path(request: AxumRequest, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    if response.status() == axum::http::StatusCode::GATEWAY_TIMEOUT {
        crate::error::timeout_response_for_path(&path)
    } else {
        response
    }
}

pub fn router(state: AppState) -> Router {
    let request_timeout = Duration::from_secs(state.config.request_timeout_seconds);
    let state_for_middleware = state.clone();

    let static_service = static_files::static_service(&state.web_dist);
    let application = routes::register(Router::new(), request_timeout).route_layer(
        from_fn_with_state(state_for_middleware.clone(), require_issuer),
    );
    let system = Router::new()
        .route("/api/v1/admin/bootstrap/status", get(health::system_status))
        // Bootstrap and issuer management must remain reachable while the issuer is
        // absent; their own extractors still enforce owner/authentication/CSRF rules.
        // bootstrap/status is anonymous but only answers initialized/uninitialized.
        .route(
            "/api/v1/admin/bootstrap",
            axum::routing::post(crate::admin::auth_handlers::bootstrap_admin),
        )
        .route(
            "/api/v1/admin/settings/issuer",
            get(crate::admin::issuer_settings_handlers::get_issuer_setting)
                .put(crate::admin::issuer_settings_handlers::update_issuer_setting),
        )
        .route("/health", get(health::health))
        .route("/health/live", get(health::health_live))
        .route("/health/ready", get(health::health_ready));
    system
        .merge(application)
        // fallback 只处理未匹配路径，协议和健康路由不会被静态服务抢走。
        .fallback_service(static_service)
        .with_state(state)
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
        .layer(from_fn(map_request_timeout_by_path))
        .layer(from_fn_with_state(
            state_for_middleware,
            apply_security_headers,
        ))
}

async fn require_issuer(
    State(state): State<AppState>,
    mut request: AxumRequest,
    next: Next,
) -> Response {
    let runtime = state.issuer.state();
    let Some(snapshot) = runtime.loaded() else {
        if crate::error::is_oauth_protocol_path(request.uri().path()) {
            return crate::error::oauth_temporarily_unavailable();
        }
        return match runtime.as_ref() {
            crate::settings::IssuerRuntimeState::AwaitingIssuer => {
                crate::error::service_unavailable(
                    "issuer_not_configured",
                    "the application issuer is not configured",
                )
            }
            crate::settings::IssuerRuntimeState::Invalid { .. } => {
                crate::error::service_unavailable(
                    "issuer_runtime_invalid",
                    "the persisted application issuer could not be loaded",
                )
            }
            crate::settings::IssuerRuntimeState::Ready(_) => unreachable!(),
        };
    };
    request.extensions_mut().insert(snapshot.clone());
    let mut response = next.run(request).await;
    response.extensions_mut().insert(snapshot);
    response
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        sqlx::{Connection, PgConnection},
    };
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header::CONTENT_TYPE},
        response::Response,
    };
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use uuid::Uuid;

    fn test_schema_name(binary_name: &str) -> String {
        let test_identity = std::env::var("NEXTEST_TEST_NAME")
            .ok()
            .filter(|name| !name.is_empty())
            .or_else(|| {
                std::thread::current()
                    .name()
                    .map(str::to_owned)
                    .filter(|name| !name.is_empty())
            })
            .unwrap_or_else(|| format!("{:?}", std::thread::current().id()));
        let readable: String = format!("ctest_{binary_name}_{test_identity}")
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let digest = Sha256::digest(format!("{binary_name}\0{test_identity}").as_bytes());
        let hash: String = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let prefix_length = 63 - hash.len() - 1;
        format!(
            "{}_{}",
            readable.chars().take(prefix_length).collect::<String>(),
            hash
        )
    }

    async fn isolated_pool(binary_name: &str, database_url: &str) -> crate::sqlx::PgPool {
        let schema = test_schema_name(binary_name);
        // 建 schema 是 owner 的活：角色分离部署下 DATABASE_URL 指向受限的运行时角色，
        // owner 连接串优先 MIGRATION_DATABASE_URL（与 tests/support/db_isolation.rs 的
        // owner_database_url 保持同一策略）；单角色环境回落 database_url，行为不变。
        let owner_url = std::env::var("MIGRATION_DATABASE_URL")
            .ok()
            .map(|url| url.trim().to_owned())
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| database_url.to_owned());
        let mut bootstrap = PgConnection::connect(&owner_url)
            .await
            .expect("db_isolation: bootstrap connection");
        crate::sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .execute(&mut bootstrap)
            .await
            .expect("db_isolation: drop schema");
        crate::sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut bootstrap)
            .await
            .expect("db_isolation: create schema");
        drop(bootstrap);

        let schema_for_pool = schema;
        // 迁移和连接 pool 都走 owner 连接：迁移会 CREATE TABLE，而受限的运行时角色
        // 对新 schema 没有 USAGE 权限，`SET search_path` 会被 PostgreSQL 静默忽略，
        // 导致迁移报 "no schema has been selected to create in"。与
        // tests/support/db_isolation.rs 的 schema_scoped_pool 保持同一策略。
        let pool = crate::sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .after_connect(move |connection, _meta| {
                let schema = schema_for_pool.clone();
                Box::pin(async move {
                    crate::sqlx::query(&format!("SET search_path TO {schema}"))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&owner_url)
            .await
            .expect("db_isolation: pool connect");

        crate::db::migrate(&pool)
            .await
            .expect("db_isolation: migrate");
        pool
    }

    /// 构造完整 Router 并发送一次请求。
    ///
    /// `web/dist` 虽然被 gitignore，但 build script 在编译期就保证了它存在
    /// （`index.html` 是 `include_str!` 的输入），因此 `AppState::new_with_pool`
    /// 里的启动期产物根校验（Issue #303）在测试环境下同样成立。
    async fn send_request(uri: &str, method: Method) -> Response {
        let request = Request::builder()
            .uri(uri)
            .method(method)
            .body(Body::empty())
            .expect("valid request");

        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned()
        });
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        let database = isolated_pool("api_mod", &database_url).await;
        let key_directory =
            std::env::temp_dir().join(format!("chenxing-api-mod-{}", Uuid::new_v4()));
        let mut config = Config::from_values_with_issuer(
            "127.0.0.1".to_owned(),
            3000,
            "http://127.0.0.1:3000".to_owned(),
            database_url,
            redis_url,
            3600,
        )
        .expect("config");
        config.cookie_secure = false;
        config.key_directory = key_directory.to_string_lossy().into_owned();
        let response = router(
            AppState::new_with_pool(config, database)
                .await
                .expect("state"),
        )
        .oneshot(request)
        .await
        .expect("router response");
        let _ = std::fs::remove_dir_all(key_directory);
        response
    }

    /// 只取 content-type 的 MIME 部分，忽略 charset 等参数。
    fn content_type(response: &Response) -> Option<&str> {
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or(value))
    }

    #[tokio::test]
    async fn spa_routes_serve_the_embedded_index_html() {
        // 客户端路由（React Router）必须拿到 index.html 而不是 404，
        // 且该行为不依赖 web/dist 是否存在，因为 index.html 是编译期内嵌的。
        let response = send_request("/console/developer", Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(content_type(&response), Some("text/html"));
    }

    #[tokio::test]
    async fn root_path_serves_the_embedded_shell_with_an_explicit_charset() {
        // 根路径必须始终由内嵌 shell 处理，而不是 ServeDir 的目录索引：
        // ServeDir 走 mime_guess，只会给出不带 charset 的 `text/html`，
        // 而调用方（含 tests/web.rs）依赖 `text/html; charset=utf-8`。
        // 这条断言同时锁定“目录索引已关闭”这一配置。
        let response = send_request("/", Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
    }

    #[tokio::test]
    async fn unknown_api_paths_return_json_not_the_spa_shell() {
        // /api 下的未知路径返回 JSON 404，避免客户端把 HTML 当 JSON 解析
        let response = send_request("/api/v1/does-not-exist", Method::GET).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(content_type(&response), Some("application/json"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
        assert_eq!(error["code"], "not_found");
    }

    #[tokio::test]
    async fn registered_api_routes_are_not_shadowed_by_the_static_service() {
        // 回归保护：静态服务挂在 fallback 上，不能抢走已注册的 API 路由。
        // 该端点要求会话，返回 401 说明请求到达了处理器而不是文件服务。
        let response = send_request("/api/v1/auth/authorized-apps", Method::GET).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_endpoint_is_not_shadowed_by_the_static_service() {
        let response = send_request("/health/live", Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(content_type(&response), Some("application/json"));
    }

    #[tokio::test]
    async fn missing_static_assets_return_json_not_found() {
        // 缺失的资源路径（带扩展名）返回 JSON 404，而不是 200 + HTML。
        // 否则浏览器会把 index.html 当作 JS 执行并报 MIME 类型错误。
        let response = send_request("/assets/missing-chunk.js", Method::GET).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(content_type(&response), Some("application/json"));
    }

    #[tokio::test]
    async fn post_to_unknown_path_returns_not_found_not_method_not_allowed() {
        // 验证 call_fallback_on_method_not_allowed(true) 生效：
        // 缺少该配置时 ServeDir 会直接返回 405，绕过统一的 404 语义。
        let response = send_request("/unknown-path", Method::POST).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// 超时中间件按请求路径分流响应格式（Issue #423）。
    ///
    /// `tower_http::timeout::TimeoutLayer` 在请求超时时返回空体 504，不携带
    /// 路径信息。`map_request_timeout_by_path` 中间件在调用下游前记录路径，
    /// 下游返回 504 时按路径选择响应格式。这里直接构造一个 504 响应并验证
    /// 中间件按路径分流到正确的协议错误格式。
    #[tokio::test]
    async fn timeout_middleware_maps_oauth_paths_to_rfc6749_errors() {
        // /oauth/token 超时必须返回 RFC 6749 temporarily_unavailable（503），
        // 而不是内部 API 信封。OAuth 客户端按 error 字段识别失败原因。
        let response = run_timeout_through_middleware("/oauth/token").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("oauth timeout body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("oauth timeout JSON");
        assert_eq!(body["error"], "temporarily_unavailable");
        assert!(body["error_description"].as_str().is_some());
        assert!(
            body.get("code").is_none(),
            "OAuth timeout must not leak API code"
        );
        assert!(
            body.get("message").is_none(),
            "OAuth timeout must not leak API message"
        );
    }

    #[tokio::test]
    async fn timeout_middleware_maps_api_paths_to_the_internal_envelope() {
        // /api/* 超时返回内部 API 信封 {code, message}，保持与既有 API 错误
        // 响应一致。这是非 OAuth 协议端点的默认行为。
        let response = run_timeout_through_middleware("/api/v1/auth/login").await;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("api timeout body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("api timeout JSON");
        assert_eq!(body["code"], "request_timeout");
        assert_eq!(body["message"], "request timed out");
        assert!(
            body.get("error").is_none(),
            "API timeout must not leak OAuth error"
        );
    }

    #[tokio::test]
    async fn timeout_middleware_preserves_non_timeout_responses() {
        // 非 504 响应必须原样通过，中间件不能改写正常响应。
        let response =
            run_through_middleware_with_status("/oauth/token", StatusCode::INTERNAL_SERVER_ERROR)
                .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// 构造一个返回 504 的下游服务，套上超时映射中间件，验证路径分流。
    ///
    /// 这条路径不依赖数据库或 Redis：中间件的职责只是「下游返回 504 时按
    /// 请求路径选择响应格式」，下游是什么不重要。
    async fn run_timeout_through_middleware(path: &str) -> Response {
        run_through_middleware_with_status(path, StatusCode::GATEWAY_TIMEOUT).await
    }

    async fn run_through_middleware_with_status(path: &str, status: StatusCode) -> Response {
        use axum::{Router, routing::get};
        let handler = move || async move { status };
        let app: Router = Router::new()
            .route(path, get(handler))
            .layer(from_fn(map_request_timeout_by_path));
        let request = Request::builder()
            .uri(path)
            .method(Method::GET)
            .body(Body::empty())
            .expect("valid request");
        app.oneshot(request).await.expect("middleware response")
    }
}
