use axum::{
    Router,
    body::Body,
    http::{
        Request, StatusCode,
        header::{CACHE_CONTROL, PRAGMA},
    },
};
use chenxing_auth::{api, state::AppState};
use tower::ServiceExt;

fn test_router() -> Router {
    api::router(AppState::for_test())
}

#[tokio::test]
async fn token_endpoint_rejects_unsupported_grant_type_without_caching() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=client_credentials&code=x&redirect_uri=https%3A%2F%2Fproject.example%2Fcallback&client_id=cx_project&client_secret=secret&code_verifier=verifier",
                ))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
}

#[tokio::test]
async fn authorization_endpoint_requires_an_authenticated_session() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/oauth/authorize?client_id=cx_project&redirect_uri=https%3A%2F%2Fproject.example%2Fcallback&response_type=code&scope=openid&state=state&code_challenge=challenge&code_challenge_method=S256")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn browser_authorization_without_a_session_redirects_to_login() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/oauth/authorize?client_id=cx_project&redirect_uri=https%3A%2F%2Fproject.example%2Fcallback&response_type=code&scope=openid&state=state&code_challenge=challenge&code_challenge_method=S256")
                .header("accept", "text/html")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("/login?request_id="))
    );
}
