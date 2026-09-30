//! Local v2 HTTP boundary: keep the platform/OAuth extractors unchanged.

use axum::{
    Json,
    extract::{FromRequest, Request, rejection::JsonRejection},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::support::{BAD_REQUEST_MESSAGE, ExchangeInput};
use crate::{error, oauth::response::with_no_store_headers};

pub struct ExchangeJson(pub ExchangeInput);

impl<S: Send + Sync> FromRequest<S> for ExchangeJson {
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Response> {
        Json::<ExchangeInput>::from_request(request, state)
            .await
            .map(|Json(input)| Self(input))
            .map_err(|rejection| {
                let code = match rejection {
                    JsonRejection::JsonSyntaxError(_) => "invalid_json",
                    _ => "invalid_request",
                };
                with_no_store_headers(error::bad_request(code, BAD_REQUEST_MESSAGE))
            })
    }
}

pub async fn retired() -> Response {
    with_no_store_headers(
        (
            StatusCode::GONE,
            Json(error::ErrorResponse {
                code: "protocol_retired".to_owned(),
                message: "use the v2 login ticket exchange".to_owned(),
            }),
        )
            .into_response(),
    )
}

/// Outside issuer/timeout middleware so even infrastructure failures cannot
/// become cacheable credentials responses or expose platform-specific codes.
pub async fn response_boundary(request: Request, next: Next) -> Response {
    let is_exchange = request.uri().path() == "/api/v2/auth/chenxing/exchange";
    let response = next.run(request).await;
    if !is_exchange {
        return response;
    }
    let response = if matches!(response.status(), StatusCode::GATEWAY_TIMEOUT) {
        error::service_unavailable("service_unavailable", "authorization state is unavailable")
    } else {
        response
    };
    with_no_store_headers(response)
}
