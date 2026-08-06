use axum::{body::Body, http::Request};
use chenxing_auth::{api, state::AppState};
use tower::ServiceExt;

#[tokio::test]
async fn rust_forwards_root_and_spa_paths_to_the_compiled_react_app() {
    let response = api::router(AppState::for_test().await)
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("root request"),
        )
        .await
        .expect("root response");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );

    let response = api::router(AppState::for_test().await)
        .oneshot(
            Request::builder()
                .uri("/console/developer")
                .body(Body::empty())
                .expect("spa request"),
        )
        .await
        .expect("spa response");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
