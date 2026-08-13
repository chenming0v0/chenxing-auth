use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use chenxing_auth::{api, config::Config, state::AppState};
use tower::ServiceExt;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

async fn unconfigured_router() -> (Router, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("issuer_routes", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("issuer-routes");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.issuer_configured = false;
    config.issuer_url.clear();
    config.cookie_secure = true;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(
            AppState::new_with_pool(config, database)
                .await
                .expect("unconfigured state"),
        ),
        key_directory,
    )
}

#[tokio::test]
async fn missing_issuer_keeps_health_and_spa_but_disables_application_routes() {
    let (router, key_directory) = unconfigured_router().await;

    for path in ["/health/live", "/login"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("allowed request"),
            )
            .await
            .expect("allowed response");
        assert_eq!(response.status(), StatusCode::OK, "path={path}");
    }

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/bootstrap/status")
                .body(Body::empty())
                .expect("status request"),
        )
        .await
        .expect("status response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("status body"),
    )
    .expect("status JSON");
    assert_eq!(body["code"], "issuer_not_configured");

    for (method, path) in [
        (Method::POST, "/api/v1/auth/login"),
        (Method::POST, "/api/v1/admin/bootstrap"),
        (Method::GET, "/.well-known/openid-configuration"),
        (Method::GET, "/.well-known/jwks.json"),
        (Method::GET, "/oauth/authorize"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("disabled request"),
            )
            .await
            .expect("disabled response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path={path}");
    }

    let _ = std::fs::remove_dir_all(key_directory);
}
