use axum::{
    Router,
    body::{Body, to_bytes},
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

async fn oauth_error_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("OAuth error body"),
    )
    .expect("OAuth error JSON")
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

    let status = response.status();
    let cache_control = response
        .headers()
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let pragma = response
        .headers()
        .get(PRAGMA)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let error = oauth_error_body(response).await;
    assert_eq!(error["error"], "unsupported_grant_type");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(cache_control.as_deref(), Some("no-store"));
    assert_eq!(pragma.as_deref(), Some("no-cache"));
}

#[tokio::test]
async fn authorization_endpoint_reports_temporary_unavailability_without_database() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/oauth/authorize?client_id=cx_project&redirect_uri=https%3A%2F%2Fproject.example%2Fcallback&response_type=code&scope=openid&state=state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let error = oauth_error_body(response).await;
    assert_eq!(error["error"], "temporarily_unavailable");
    assert_eq!(
        error["error_description"],
        "the authorization server is temporarily unable to handle the request"
    );
}

#[tokio::test]
async fn browser_authorization_reports_temporary_unavailability_without_database() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/oauth/authorize?client_id=cx_project&redirect_uri=https%3A%2F%2Fproject.example%2Fcallback&response_type=code&scope=openid&state=state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
                .header("accept", "text/html")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let error = oauth_error_body(response).await;
    assert_eq!(error["error"], "temporarily_unavailable");
    assert_eq!(
        error["error_description"],
        "the authorization server is temporarily unable to handle the request"
    );
}
