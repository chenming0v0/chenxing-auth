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
async fn userinfo_requires_bearer_token() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_management_requires_admin_bearer_token() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"client_name":"项目","redirect_uris":["https://project.example/callback"],"scopes":["openid"]}"#,
                ))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
