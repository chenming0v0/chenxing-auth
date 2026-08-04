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
    use super::{oauth_invalid_bearer, oauth_invalid_client};
    use axum::{body::to_bytes, http::header::WWW_AUTHENTICATE};

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
}
