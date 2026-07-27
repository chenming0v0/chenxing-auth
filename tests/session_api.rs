use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::{api, state::AppState};
use tower::ServiceExt;

fn test_router() -> Router {
    api::router(AppState::for_test())
}

#[tokio::test]
async fn session_revoke_requires_a_valid_session_header() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/auth/session")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
