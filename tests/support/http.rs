#![allow(dead_code)]

//! 共享 HTTP 请求 / 响应助手，纯内存调用，不触碰数据库。
//!
//! 这些助手在 49 个测试文件里被反复手抄，签名逐渐漂移。这里收敛成一组统一的
//! 纯函数：请求经 `tower::ServiceExt::oneshot` 直接打进 Router，响应按需要提取
//! JSON、Set-Cookie、`Location`。
//!
//! 调用方须在目标的 `mod.rs` 声明：
//!
//! ```rust,ignore
//! #[path = "../support/http.rs"]
//! mod http;
//! ```

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Request,
        header::{LOCATION, SET_COOKIE},
    },
    response::Response,
};
use serde_json::Value;
use tower::ServiceExt;

/// 读取响应体并解析为 JSON。非 JSON 或非法 JSON 会 panic，测试应当早失败。
pub async fn json_body(response: Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

/// 把每个 `Set-Cookie` 头的首个 `name=value` 段拼成可直接回填的 Cookie 请求头。
///
/// 与 `oauth_flow::cookie_header` 保持一致：忽略不可转成 UTF-8 的头值。
pub fn set_cookies(response: &Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().expect("cookie pair"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// 从 Cookie 请求头中取出指定名字的值。
pub fn cookie_value(cookie_header: &str, name: &str) -> String {
    cookie_header
        .split(';')
        .find_map(|part| part.trim().strip_prefix(&format!("{name}=")))
        .expect("cookie present")
        .to_owned()
}

/// 读取重定向响应的 `Location` 头。
pub fn location(response: &Response) -> String {
    response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location")
        .to_owned()
}

/// `POST` JSON 负载。
pub async fn post_json(router: &Router, uri: &str, payload: Value) -> Response {
    post_json_with_headers(router, uri, &[], payload).await
}

/// 带自定义请求头的 `POST` JSON 负载。`content-type` 由本函数补齐。
pub async fn post_json_with_headers(
    router: &Router,
    uri: &str,
    headers: &[(&str, &str)],
    payload: Value,
) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    router
        .clone()
        .oneshot(
            builder
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

/// `GET`，可带自定义请求头。
pub async fn get(router: &Router, uri: &str, headers: &[(&str, &str)]) -> Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    router
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response")
}

/// 发送任意已构建的请求。
pub async fn send(router: &Router, request: Request<Body>) -> Response {
    router.clone().oneshot(request).await.expect("response")
}
