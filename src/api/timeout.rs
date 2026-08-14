use axum::{
    extract::Request as AxumRequest, http::StatusCode, middleware::Next, response::Response,
};
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;

/// 应用路由和 system API 共用的请求超时层。
///
/// `TimeoutLayer` 默认返回空体 `text/plain`。这里固定打出 504，让
/// [`map_request_timeout_by_path`] 把它改写成项目统一 JSON 信封。
/// 健康探针有自己的 2 秒依赖预算，静态 SPA fallback 可能流式读文件，
/// 两者都不能套这一层。
pub(super) fn request_timeout_layer(request_timeout: Duration) -> TimeoutLayer {
    TimeoutLayer::with_status_code(StatusCode::GATEWAY_TIMEOUT, request_timeout)
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
pub(super) async fn map_request_timeout_by_path(request: AxumRequest, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    if response.status() == StatusCode::GATEWAY_TIMEOUT {
        crate::error::timeout_response_for_path(&path)
    } else {
        response
    }
}

#[cfg(test)]
mod tests {
    use super::{map_request_timeout_by_path, request_timeout_layer};
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header::CONTENT_TYPE},
        middleware::from_fn,
        response::Response,
        routing::{get, post},
    };
    use std::{
        future,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tower::ServiceExt;

    const SYSTEM_TIMEOUT: Duration = Duration::from_millis(40);
    const BOOTSTRAP_STATUS: &str = "/api/v1/admin/bootstrap/status";
    const BOOTSTRAP: &str = "/api/v1/admin/bootstrap";
    const ISSUER: &str = "/api/v1/admin/settings/issuer";

    /// 测试里可切换的挂起依赖：未释放时 `wait` 永不结束，释放后立即返回。
    #[derive(Clone)]
    struct HangSwitch {
        released: Arc<AtomicBool>,
    }

    impl HangSwitch {
        fn hanging() -> Self {
            Self {
                released: Arc::new(AtomicBool::new(false)),
            }
        }

        fn ready() -> Self {
            Self {
                released: Arc::new(AtomicBool::new(true)),
            }
        }

        async fn wait(&self) {
            if self.released.load(Ordering::SeqCst) {
                return;
            }
            future::pending::<()>().await;
        }
    }

    async fn system_handler(switch: HangSwitch) -> StatusCode {
        switch.wait().await;
        StatusCode::OK
    }

    fn system_api(switch: HangSwitch) -> Router {
        Router::new()
            .route(
                BOOTSTRAP_STATUS,
                get({
                    let switch = switch.clone();
                    move || system_handler(switch.clone())
                }),
            )
            .route(
                BOOTSTRAP,
                post({
                    let switch = switch.clone();
                    move || system_handler(switch.clone())
                }),
            )
            .route(
                ISSUER,
                get({
                    let switch = switch.clone();
                    move || system_handler(switch.clone())
                })
                .put({
                    let switch = switch.clone();
                    move || system_handler(switch.clone())
                }),
            )
            .route_layer(request_timeout_layer(SYSTEM_TIMEOUT))
    }

    fn stacked(system: Router, health: Router) -> Router {
        system
            .merge(health)
            .layer(from_fn(map_request_timeout_by_path))
    }

    async fn send(app: Router, method: Method, path: &str) -> Response {
        app.oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router response")
    }

    async fn json_body(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        serde_json::from_slice(&body).expect("JSON body")
    }

    fn content_type(response: &Response) -> Option<&str> {
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or(value))
    }

    async fn assert_timeout_envelope(response: Response) {
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            content_type(&response),
            Some("application/json"),
            "timeout must not leak tower's default text/plain"
        );
        let body = json_body(response).await;
        assert_eq!(body["code"], "request_timeout");
        assert_eq!(body["message"], "request timed out");
        assert!(body.get("error").is_none());
    }

    #[tokio::test]
    async fn hanging_system_endpoints_return_the_shared_json_timeout() {
        let app = stacked(system_api(HangSwitch::hanging()), Router::new());
        for (method, path) in [
            (Method::GET, BOOTSTRAP_STATUS),
            (Method::POST, BOOTSTRAP),
            (Method::GET, ISSUER),
            (Method::PUT, ISSUER),
        ] {
            assert_timeout_envelope(send(app.clone(), method, path).await).await;
        }
    }

    #[tokio::test]
    async fn ready_system_endpoints_do_not_time_out() {
        let app = stacked(system_api(HangSwitch::ready()), Router::new());
        for (method, path) in [
            (Method::GET, BOOTSTRAP_STATUS),
            (Method::POST, BOOTSTRAP),
            (Method::GET, ISSUER),
            (Method::PUT, ISSUER),
        ] {
            let response = send(app.clone(), method, path).await;
            assert_eq!(response.status(), StatusCode::OK, "path={path}");
        }
    }

    #[tokio::test]
    async fn hanging_health_is_not_wrapped_by_the_system_timeout_layer() {
        let health = Router::new().route(
            "/health/live",
            get(|| async {
                HangSwitch::hanging().wait().await;
                StatusCode::OK
            }),
        );
        let app = stacked(system_api(HangSwitch::hanging()), health);

        let system = send(app.clone(), Method::GET, BOOTSTRAP_STATUS).await;
        assert_timeout_envelope(system).await;

        let health = tokio::time::timeout(
            SYSTEM_TIMEOUT + Duration::from_millis(30),
            send(app, Method::GET, "/health/live"),
        )
        .await;
        assert!(
            health.is_err(),
            "health must keep hanging; the system TimeoutLayer must not wrap it"
        );
    }

    #[tokio::test]
    async fn timeout_middleware_maps_oauth_paths_to_rfc6749_errors() {
        // /oauth/token 超时必须返回 RFC 6749 temporarily_unavailable（503），
        // 而不是内部 API 信封。OAuth 客户端按 error 字段识别失败原因。
        let response = run_timeout_through_middleware("/oauth/token").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = json_body(response).await;
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

        let body = json_body(response).await;
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
        let handler = move || async move { status };
        let app: Router = Router::new()
            .route(path, get(handler))
            .layer(from_fn(map_request_timeout_by_path));
        send(app, Method::GET, path).await
    }
}
