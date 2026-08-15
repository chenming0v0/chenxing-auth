use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    routing::post,
};
use serde::Deserialize;
use tower::ServiceExt;

use super::{ApiJson, optional_session};

#[derive(Deserialize)]
struct Input {
    count: u32,
}

async fn accept(ApiJson(input): ApiJson<Input>) -> String {
    input.count.to_string()
}

async fn rejection(
    body: &'static str,
    content_type: Option<&'static str>,
    expected_status: StatusCode,
) -> serde_json::Value {
    let mut request = Request::builder().method("POST").uri("/");
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    let response = Router::new()
        .route("/", post(accept))
        .oneshot(request.body(Body::from(body)).expect("request"))
        .await
        .expect("response");
    assert_eq!(response.status(), expected_status);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("error envelope")
}

#[tokio::test]
async fn json_rejections_use_a_stable_envelope_without_serde_details() {
    for (body, status) in [
        (
            r#"{"count":"secret-type-detail"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        ("{", StatusCode::BAD_REQUEST),
    ] {
        let response = rejection(body, Some("application/json"), status).await;
        assert_eq!(response["code"], "invalid_json");
        assert_eq!(response["message"], "request body must be valid JSON");
        assert!(!response.to_string().contains("count"));
        assert!(!response.to_string().contains("u32"));
    }
}

#[tokio::test]
async fn missing_json_content_type_uses_the_same_contract() {
    let response = rejection(r#"{"count":1}"#, None, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;
    assert_eq!(response["code"], "unsupported_media_type");
    assert_eq!(
        response["message"],
        "request Content-Type must be application/json"
    );
}

#[test]
fn optional_session_only_swallows_explicit_unauthenticated_responses() {
    let unauthenticated = optional_session(Err(crate::error::unauthorized(
        "login_required",
        "an authenticated session is required",
    )))
    .expect("401 should become an absent optional session");
    assert!(unauthenticated.is_none());

    let internal = optional_session(Err(crate::error::internal()))
        .expect_err("internal failures must remain extractor rejections");
    assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
