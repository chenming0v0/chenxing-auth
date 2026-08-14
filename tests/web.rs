use axum::{
    Router,
    body::Body,
    http::{
        HeaderName, Method, Request, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
    response::Response,
};
use chenxing_auth::{api, config::Config, state::AppState};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

async fn spa_response(router: Router, uri: &str) -> Response {
    router
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("SPA request"),
        )
        .await
        .expect("SPA response")
}

async fn assert_spa_shell(router: Router, uri: &str) {
    let response = spa_response(router, uri).await;
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8"),
        "{uri}"
    );
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache"),
        "{uri}"
    );
}

async fn assert_json_not_found(router: Router, method: Method, uri: &str) {
    let response = router
        .oneshot(
            Request::builder()
                .method(method.clone())
                .uri(uri)
                .body(Body::empty())
                .expect("protocol 404 request"),
        )
        .await
        .expect("protocol 404 response");
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "{method} {uri} must not be SPA 200"
    );
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {uri}");
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or(value)),
        Some("application/json"),
        "{method} {uri}"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("protocol 404 body");
    let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
    assert_eq!(error["code"], "not_found", "{method} {uri}");
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
        assert_json_not_found(router.clone(), Method::GET, uri).await;
    }
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 未知路径或已注册 SPA 路径上的非 GET/HEAD 必须走统一 JSON 信封，
/// 不能落到 text/plain，也不能回退成 SPA shell。
#[tokio::test]
async fn unknown_non_get_paths_return_json_not_found() {
    let (router, key_directory) = test_router().await;

    assert_json_not_found(router.clone(), Method::POST, "/api/v1/does-not-exist").await;
    assert_json_not_found(router.clone(), Method::PUT, "/oauth/does-not-exist").await;
    assert_json_not_found(router.clone(), Method::DELETE, "/oauth/account").await;
    assert_json_not_found(router.clone(), Method::POST, "/index.html").await;
    assert_spa_shell(router, "/console/developer").await;

    let _ = std::fs::remove_dir_all(key_directory);
}

fn embedded_hashed_script_path() -> &'static str {
    let html = chenxing_auth::web_dist::EMBEDDED_INDEX_HTML;
    let marker = "src=\"";
    let mut rest = html;
    while let Some(start) = rest.find(marker) {
        rest = &rest[start + marker.len()..];
        let Some(end) = rest.find('"') else { break };
        let value = &rest[..end];
        if value.starts_with("/assets/") && value.ends_with(".js") {
            return value;
        }
        rest = &rest[end + 1..];
    }
    panic!("embedded SPA shell has no hashed script");
}

/// 内容哈希 assets 可以永久缓存；根上没有哈希的图标不能 immutable。
#[tokio::test]
async fn content_hashed_assets_are_immutable_and_unhashed_files_are_not() {
    let (router, key_directory) = test_router().await;
    let hashed = embedded_hashed_script_path();

    let hashed_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(hashed)
                .body(Body::empty())
                .expect("hashed asset request"),
        )
        .await
        .expect("hashed asset response");
    assert_eq!(hashed_response.status(), StatusCode::OK, "{hashed}");
    assert_eq!(
        hashed_response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=31536000, immutable"),
        "{hashed}"
    );

    let favicon = router
        .oneshot(
            Request::builder()
                .uri("/favicon.png")
                .body(Body::empty())
                .expect("favicon request"),
        )
        .await
        .expect("favicon response");
    assert_eq!(favicon.status(), StatusCode::OK);
    let cache = favicon
        .headers()
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        !cache.contains("immutable"),
        "unhashed favicon must not be immutable: {cache}"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

/// `/` 走 SPA fallback，`/index.html` 是盘上的真实文件。两条路径必须返回
/// 同一份内嵌 shell，否则半次发布会让浏览器加载两套资源引用。
#[tokio::test]
async fn root_and_index_html_serve_the_same_embedded_shell() {
    let (router, key_directory) = test_router().await;

    let root = spa_response(router.clone(), "/").await;
    let index = spa_response(router, "/index.html").await;

    assert_eq!(root.status(), StatusCode::OK);
    assert_eq!(index.status(), StatusCode::OK);

    let root_headers = root.headers().clone();
    let index_headers = index.headers().clone();
    let root_body = axum::body::to_bytes(root.into_body(), usize::MAX)
        .await
        .expect("root body");
    let index_body = axum::body::to_bytes(index.into_body(), usize::MAX)
        .await
        .expect("index.html body");

    assert_eq!(
        root_body, index_body,
        "/ and /index.html must be the same bytes"
    );
    assert_eq!(
        root_headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );

    for name in [
        CONTENT_TYPE,
        CACHE_CONTROL,
        HeaderName::from_static("content-security-policy"),
        HeaderName::from_static("x-frame-options"),
        HeaderName::from_static("x-content-type-options"),
        HeaderName::from_static("referrer-policy"),
    ] {
        assert_eq!(
            root_headers.get(&name),
            index_headers.get(&name),
            "{name} must match between / and /index.html"
        );
    }

    let _ = std::fs::remove_dir_all(key_directory);
}
