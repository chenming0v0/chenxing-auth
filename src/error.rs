use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
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
