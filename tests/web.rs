use axum::{body::Body, http::Request};
use chenxing_auth::{api, state::AppState, web::escape_html};
use tower::ServiceExt;

#[test]
fn browser_html_escapes_untrusted_values() {
    assert_eq!(
        escape_html("<script>alert(\"x\")</script>"),
        "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
    );
}

#[tokio::test]
async fn rust_serves_compiled_web_at_root_and_spa_paths() {
    let response = api::router(AppState::for_test())
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

    let response = api::router(AppState::for_test())
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
