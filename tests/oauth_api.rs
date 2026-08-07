use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{CACHE_CONTROL, PRAGMA},
    },
};
use chenxing_auth::{api, config::Config, state::AppState};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

async fn test_router() -> (Router, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("oauth_api", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-oauth-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(
            AppState::new_with_pool(config, database)
                .await
                .expect("state"),
        ),
        key_directory,
    )
}

async fn test_router_no_db() -> (Router, std::path::PathBuf) {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-oauth-nodb-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        "postgres://127.0.0.1:9999/nonexistent".to_owned(),
        redis_url,
        3600,
    )
    .expect("config");
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(AppState::new(config).await.expect("state")),
        key_directory,
    )
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
    let (router, key_directory) = test_router().await;
    let response = router
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
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn authorization_endpoint_reports_temporary_unavailability_without_database() {
    let (router, key_directory) = test_router_no_db().await;
    let response = router
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
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn browser_authorization_reports_temporary_unavailability_without_database() {
    let (router, key_directory) = test_router_no_db().await;
    let response = router
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
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn malformed_token_form_returns_rfc_oauth_error() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=%ZZ"))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = oauth_error_body(response).await;
    assert_eq!(error["error"], "invalid_request");
    assert!(error.get("code").is_none());
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn malformed_authorization_query_returns_rfc_oauth_error() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/oauth/authorize?%ZZ")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = oauth_error_body(response).await;
    assert_eq!(error["error"], "invalid_request");
    assert!(error.get("code").is_none());
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn malformed_authorization_form_returns_rfc_oauth_error() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/authorize")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("client_id=%ZZ"))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = oauth_error_body(response).await;
    assert_eq!(error["error"], "invalid_request");
    assert!(error.get("code").is_none());
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn malformed_userinfo_form_returns_rfc_oauth_error() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/userinfo")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("access_token=%ZZ"))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = oauth_error_body(response).await;
    assert_eq!(error["error"], "invalid_request");
    assert!(error.get("code").is_none());
    let _ = std::fs::remove_dir_all(key_directory);
}
