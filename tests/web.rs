use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use chenxing_auth::{api, config::Config, state::AppState};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

async fn assert_spa_shell(router: Router, uri: &str) {
    let response = router
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("SPA request"),
        )
        .await
        .expect("SPA response");
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8"),
        "{uri}"
    );
}

async fn assert_json_not_found(router: Router, uri: &str) {
    let response = router
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("protocol 404 request"),
        )
        .await
        .expect("protocol 404 response");
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "{uri} must not be SPA 200"
    );
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or(value)),
        Some("application/json"),
        "{uri}"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("protocol 404 body");
    let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
    assert_eq!(error["code"], "not_found", "{uri}");
}

async fn test_router() -> (axum::Router, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("web", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-web-{}", Uuid::new_v4()));
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

#[tokio::test]
async fn rust_forwards_root_and_spa_paths_to_the_compiled_react_app() {
    let (router, key_directory) = test_router().await;
    for uri in [
        "/",
        "/console/developer",
        "/oauth/account",
        "/oauth/consent?request_id=test-request",
        "/oauth/redirect?redirect_to=https%3A%2F%2Fclient.example%2Fcallback",
    ] {
        assert_spa_shell(router.clone(), uri).await;
    }

    // 未注册的 /oauth/* 是协议空间，不能回退成 200 HTML，否则 OAuth 客户端
    // 会把拼错的授权 URL 当成成功页。尾斜杠和子路径同样拒绝。
    for uri in [
        "/oauth/does-not-exist",
        "/oauth/does-not-exist/",
        "/oauth/consent/xxx",
    ] {
        assert_json_not_found(router.clone(), uri).await;
    }
    let _ = std::fs::remove_dir_all(key_directory);
}
