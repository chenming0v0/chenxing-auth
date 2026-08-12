use axum::{
    Router,
    http::{HeaderMap, Request},
    middleware::map_response,
    response::Response,
};
use std::{net::SocketAddr, time::Duration};
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

pub fn router(state: AppState) -> Router {
    let hsts_enabled = security_headers::hsts_enabled(&state.config.issuer_url);
    let request_timeout = Duration::from_secs(state.config.request_timeout_seconds);

    // 静态根来自 AppState 里那份启动期已校验的路径，请求路径上不再读环境变量。
    let static_service = static_files::static_service(&state.web_dist);

    routes::register(Router::new(), request_timeout)
        // 静态资源与 SPA 回退挂在 fallback 上：fallback_service 只在上面所有
        // 路由都不匹配时才生效，所以 /api/*、/health 等不会被静态服务抢走。
        .fallback_service(static_service)
        .with_state(state)
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
        .layer(map_response(|response: Response| async move {
            crate::error::map_request_timeout(response)
        }))
        .layer(map_response(move |response: Response| {
            security_headers::apply(response, hsts_enabled)
        }))
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
        let mut bootstrap = PgConnection::connect(database_url)
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
            .connect(database_url)
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
}
