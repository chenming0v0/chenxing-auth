use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
};
use chenxing_auth::{api, config::Config, settings::IssuerRuntime, state::AppState};
use tower::ServiceExt;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

async fn restricted_router(invalid: bool) -> (Router, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("issuer_routes", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("issuer-routes");
    let mut config =
        Config::from_values("127.0.0.1".to_owned(), 3000, database_url, redis_url, 3600)
            .expect("config");
    config.issuer = None;
    config.cookie_secure = true;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let mut state = AppState::new_with_pool(config, database)
        .await
        .expect("restricted state");
    if invalid {
        state.issuer = IssuerRuntime::new_invalid(&state.config, 1);
    }
    (api::router(state), key_directory)
}

#[tokio::test]
async fn missing_issuer_keeps_health_and_spa_but_disables_application_routes() {
    let (router, key_directory) = restricted_router(false).await;

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
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("status body"),
    )
    .expect("status JSON");
    assert_eq!(body["initialized"], false);

    for (method, path) in [
        (Method::POST, "/api/v1/auth/login"),
        (Method::GET, "/.well-known/openid-configuration"),
        (Method::GET, "/.well-known/jwks.json"),
        (Method::GET, "/oauth/authorize"),
    ] {
        let body = (path == "/api/v1/auth/login").then_some(Body::from("{}"));
        let mut request = Request::builder().method(method).uri(path);
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let response = router
            .clone()
            .oneshot(
                request
                    .body(body.unwrap_or_else(Body::empty))
                    .expect("disabled request"),
            )
            .await
            .expect("disabled response");
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "path={path}"
        );
    }

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn issuer_gate_uses_oauth_envelope_only_for_registered_protocol_endpoints() {
    for invalid in [false, true] {
        let (router, key_directory) = restricted_router(invalid).await;

        for (method, path) in [
            (Method::GET, "/oauth/authorize"),
            (Method::POST, "/oauth/token"),
            (Method::POST, "/oauth/revoke"),
            (Method::GET, "/oauth/userinfo"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .expect("OAuth request"),
                )
                .await
                .expect("OAuth response");
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "invalid={invalid}, path={path}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(';').next()),
                Some("application/json"),
                "invalid={invalid}, path={path}"
            );
            let body: serde_json::Value = serde_json::from_slice(
                &to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("OAuth response body"),
            )
            .expect("OAuth response JSON");
            assert_eq!(body["error"], "temporarily_unavailable");
            assert!(body["error_description"].as_str().is_some());
            assert!(body.get("code").is_none());
            assert!(body.get("message").is_none());
        }

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/oauth/not-registered")
                    .body(Body::empty())
                    .expect("unknown OAuth path request"),
            )
            .await
            .expect("unknown OAuth path response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(key_directory);
    }
}
