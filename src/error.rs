use axum::{
    Json,
    http::{HeaderValue, StatusCode, header::WWW_AUTHENTICATE},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

pub fn oauth_bad_request(code: &'static str, description: impl Into<String>) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, code, description)
}

pub fn oauth_too_many_requests(code: &'static str, description: impl Into<String>) -> Response {
    oauth_error(StatusCode::TOO_MANY_REQUESTS, code, description)
}

pub fn oauth_server_error() -> Response {
    oauth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "the authorization server encountered an unexpected condition",
    )
}

pub fn oauth_temporarily_unavailable() -> Response {
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "the authorization server is temporarily unable to handle the request",
    )
}

pub(crate) fn request_timeout() -> Response {
    (
        StatusCode::GATEWAY_TIMEOUT,
        Json(ErrorResponse {
            code: "request_timeout".to_owned(),
            message: "request timed out".to_owned(),
        }),
    )
        .into_response()
}

/// 按请求路径映射超时响应。
///
/// `tower_http::timeout::TimeoutLayer` 在请求超时时返回空体 504 响应。调用方
/// （`api::timeout::map_request_timeout_by_path` 中间件）捕获请求路径后调用本函数，按
/// 协议边界选择响应格式：
///
/// - 已注册的 OAuth 协议端点返回 RFC 6749 错误（503
///   `temporarily_unavailable`），与端点的其他错误响应一致。
/// - 其余路径返回项目内部 API 信封 `{code, message}`（504 `request_timeout`）。
///
/// 这是协议边界，不是路径前缀约定：`/api/v1/oauth/*`（授权确认 API）属于内部
/// API，仍返回 API 信封。
pub(crate) fn timeout_response_for_path(path: &str) -> Response {
    if is_oauth_protocol_path(path) {
        oauth_temporarily_unavailable()
    } else {
        request_timeout()
    }
}

/// OAuth 2.0 协议端点路径判定。
///
/// 只识别实际注册的 RFC 6749/6750/7009 端点。不能按 `/oauth/` 前缀放宽，
/// 否则未知路径会被错误分类为协议端点，而不是保持统一 404。
pub(crate) fn is_oauth_protocol_path(path: &str) -> bool {
    matches!(
        path,
        "/oauth/authorize" | "/oauth/token" | "/oauth/revoke" | "/oauth/userinfo"
    )
}

pub fn oauth_unauthorized(
    code: &'static str,
    description: impl Into<String>,
    challenge: &str,
) -> Response {
    let mut response = oauth_error(StatusCode::UNAUTHORIZED, code, description);
    if let Ok(value) = HeaderValue::from_str(challenge) {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    response
}

pub fn oauth_invalid_client() -> Response {
    oauth_unauthorized(
        "invalid_client",
        "client authentication failed",
        "Basic realm=\"oauth\"",
    )
}

pub fn oauth_invalid_bearer(description: &'static str) -> Response {
    oauth_unauthorized(
        "invalid_token",
        description,
        &format!(
            "Bearer realm=\"oauth\", error=\"invalid_token\", error_description=\"{}\"",
            description.replace('"', "\\\"")
        ),
    )
}

fn oauth_error(status: StatusCode, code: &'static str, description: impl Into<String>) -> Response {
    (
        status,
        Json(OAuthErrorResponse {
            error: code.to_owned(),
            error_description: Some(description.into()),
        }),
    )
        .into_response()
}

pub fn bad_request(code: &'static str, message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            code: code.to_owned(),
            message: message.into(),
        }),
    )
        .into_response()
}

pub fn conflict(code: &'static str, message: impl Into<String>) -> Response {
    (
        StatusCode::CONFLICT,
        Json(ErrorResponse {
            code: code.to_owned(),
            message: message.into(),
        }),
    )
        .into_response()
}

pub fn unauthorized(code: &'static str, message: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            code: code.to_owned(),
            message: message.into(),
        }),
    )
        .into_response()
}

pub fn forbidden(code: &'static str, message: impl Into<String>) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            code: code.to_owned(),
            message: message.into(),
        }),
    )
        .into_response()
}

/// `ADMIN_TOKEN` 未配置时管理面整体关闭的统一拒绝响应（AGENTS.md，Issue #348）。
///
/// 用 403 而不是 401：即使携带有效凭据（系统 Token 或管理 Session）也无法访问，
/// 401 会误导调用方去重新登录。所有调用者拿到同一响应，也避免把「是否配置了
/// `ADMIN_TOKEN`」变成按调用通道区分的探测预言机。
pub fn admin_disabled() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            code: "admin_disabled".to_owned(),
            message: "administrator API is disabled because ADMIN_TOKEN is not configured"
                .to_owned(),
        }),
    )
        .into_response()
}

pub fn not_found(code: &'static str, message: impl Into<String>) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            code: code.to_owned(),
            message: message.into(),
        }),
    )
        .into_response()
}

pub fn too_many_requests(code: &'static str, message: impl Into<String>) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ErrorResponse {
            code: code.to_owned(),
            message: message.into(),
        }),
    )
        .into_response()
}

pub fn service_unavailable(code: &'static str, message: impl Into<String>) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            code: code.to_owned(),
            message: message.into(),
        }),
    )
        .into_response()
}

pub fn internal() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            code: "internal_error".to_owned(),
            message: "internal server error".to_owned(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        is_oauth_protocol_path, oauth_invalid_bearer, oauth_invalid_client,
        timeout_response_for_path,
    };
    use axum::{
        body::to_bytes,
        http::{StatusCode, header::WWW_AUTHENTICATE},
    };

    #[tokio::test]
    async fn oauth_client_error_has_rfc_fields_and_basic_challenge() {
        let response = oauth_invalid_client();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Basic realm=\"oauth\"")
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("OAuth error body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("OAuth error JSON");
        assert_eq!(body["error"], "invalid_client");
        assert!(body["error_description"].as_str().is_some());
        assert!(body.get("code").is_none());
    }

    #[tokio::test]
    async fn bearer_error_has_invalid_token_challenge_without_token_details() {
        let response = oauth_invalid_bearer("access token is invalid");
        let challenge = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .expect("Bearer challenge");
        assert!(challenge.starts_with("Bearer realm=\"oauth\""));
        assert!(challenge.contains("error=\"invalid_token\""));
        assert!(!challenge.contains("expired"));
    }

    #[test]
    fn oauth_server_error_uses_protocol_error_field() {
        let response = super::oauth_server_error();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn request_timeout_uses_generic_json_without_internal_details() {
        let response = timeout_response_for_path("/api/v1/auth/login");
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("request timeout body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("request timeout JSON");
        assert_eq!(body["code"], "request_timeout");
        assert_eq!(body["message"], "request timed out");
        assert!(body.get("error").is_none());
    }

    #[tokio::test]
    async fn oauth_protocol_timeout_returns_rfc6749_temporarily_unavailable() {
        // /oauth/token 等协议端点超时必须返回 RFC 6749 错误信封，而不是内部
        // API 信封，否则 OAuth 客户端无法按 error 字段识别失败原因。
        for path in [
            "/oauth/token",
            "/oauth/authorize",
            "/oauth/revoke",
            "/oauth/userinfo",
        ] {
            let response = timeout_response_for_path(path);
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{path} status"
            );

            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("oauth timeout body");
            let body: serde_json::Value =
                serde_json::from_slice(&body).expect("oauth timeout JSON");
            assert_eq!(body["error"], "temporarily_unavailable", "{path} error");
            assert!(
                body["error_description"].as_str().is_some(),
                "{path} error_description"
            );
            assert!(body.get("code").is_none(), "{path} must not leak API code");
            assert!(
                body.get("message").is_none(),
                "{path} must not leak API message"
            );
        }
    }

    #[test]
    fn oauth_protocol_path_detection_covers_rfc6749_endpoints_only() {
        for path in [
            "/oauth/token",
            "/oauth/authorize",
            "/oauth/revoke",
            "/oauth/userinfo",
        ] {
            assert!(is_oauth_protocol_path(path), "{path} should be OAuth");
        }

        // OIDC Discovery、内部 API、授权确认 API、静态资源、SPA 路由都不是
        // RFC 6749 协议端点，超时时返回 API 信封。
        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
            "/api/v1/auth/login",
            "/api/v1/oauth/authorize/requests/abc",
            "/oauth/authorize/decide",
            "/oauth/not-registered",
            "/oauth/consent",
            "/health/live",
            "/admin/login",
            "/console/developer",
            "/assets/app.js",
            "/",
        ] {
            assert!(!is_oauth_protocol_path(path), "{path} should not be OAuth");
        }
    }
}
