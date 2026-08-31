use crate::db_isolation;
use crate::key_directory;
use axum::{
    Router,
    body::Body,
    http::{
        Request, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
};
use chenxing_auth::{api, config::Config, state::AppState};
use tower::ServiceExt;

async fn test_router() -> (Router, std::path::PathBuf) {
    test_router_with_issuer(true).await
}

async fn test_router_without_issuer() -> (Router, std::path::PathBuf) {
    test_router_with_issuer(false).await
}

async fn test_router_with_issuer(configure_issuer: bool) -> (Router, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("api", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("api");
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    if !configure_issuer {
        config.issuer = None;
    }
    // Issue #348：ADMIN_TOKEN 为空时管理面整体关闭，未认证请求拿到的是 403
    // admin_disabled 而不是守卫的 401。这两个用例的意图是「请求落到 AdminWrite
    // 守卫并被拒绝」，因此显式启用管理面（非空 Token），让守卫真正执行。
    config.admin_token = "api-test-admin".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database)
        .await
        .expect("state");
    state.worker_health.assume_ready_for_test();
    (api::router(state), key_directory)
}

async fn jwks_response(router: Router) -> (axum::http::HeaderMap, Vec<u8>) {
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    (headers, body.to_vec())
}

#[tokio::test]
async fn liveness_endpoint_reports_process_status_without_dependencies() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn liveness_endpoint_does_not_expand_jwks_cors() {
    // Issue #442：JWKS 的 ACEH / ACAO 不得扩到非 JWKS 路由。
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .header("origin", "https://relying-party.example.com")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    assert!(
        response
            .headers()
            .get("access-control-expose-headers")
            .is_none()
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn liveness_endpoint_includes_security_headers_without_hsts_for_http_issuer() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.headers()["x-frame-options"], "DENY");
    // 健康检查返回 JSON，不是文档，拿到的是不可加载任何资源的严格策略。
    assert_eq!(
        response.headers()["content-security-policy"],
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert!(
        response
            .headers()
            .get("strict-transport-security")
            .is_none()
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn the_spa_shell_gets_a_document_csp_that_allows_its_real_assets() {
    // #262：全局 CSP 曾只有 frame-ancestors，对脚本注入毫无约束。
    // SPA 文档必须拿到一条覆盖 default/script/object/base/form/frame 的策略，
    // 同时保留 React 产物真实需要的 data:（二维码）和 blob:（头像预览）图片源。
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/console/developer")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    let policy = response.headers()["content-security-policy"]
        .to_str()
        .expect("ASCII policy")
        .to_owned();

    for directive in [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data: blob:",
        "object-src 'none'",
        "frame-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ] {
        assert!(
            policy.contains(directive),
            "missing {directive} in {policy}"
        );
    }
    assert!(!policy.contains("unsafe-inline"), "{policy}");
    assert!(!policy.contains("unsafe-eval"), "{policy}");

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn readiness_endpoint_returns_a_dependency_agnostic_failure_body() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert!(matches!(
        response.status(),
        StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
    ));
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("readiness body");
    let body = String::from_utf8(body.to_vec()).expect("UTF-8 readiness body");
    assert!(!body.contains("postgres"));
    assert!(!body.contains("redis://"));
    assert!(!body.contains("127.0.0.1"));
    let _ = std::fs::remove_dir_all(key_directory);
}

/// Issue #445：三个探针都禁止缓存。缺少 Issuer 是可恢复的引导状态，数据库和
/// Redis 正常时三个探针都返回 200。
#[tokio::test]
async fn health_probes_are_not_stored_when_issuer_is_truly_absent() {
    let (router, key_directory) = test_router_without_issuer().await;

    for (path, expected) in [
        ("/health/live", StatusCode::OK),
        ("/health", StatusCode::OK),
        ("/health/ready", StatusCode::OK),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("health request"),
            )
            .await
            .expect("health response");
        assert_eq!(response.status(), expected, "{path}");
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "{path}"
        );
    }

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn health_rejects_a_runtime_issuer_that_is_not_persisted() {
    let (router, key_directory) = test_router().await;

    for (path, expected) in [
        ("/health/live", StatusCode::OK),
        ("/health", StatusCode::SERVICE_UNAVAILABLE),
        ("/health/ready", StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("health request"),
            )
            .await
            .expect("health response");
        assert_eq!(response.status(), expected, "{path}");
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "{path}"
        );
    }

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn authorized_apps_endpoint_requires_a_session() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/authorized-apps")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn openid_configuration_publishes_standard_endpoints() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let configuration: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(
        configuration["revocation_endpoint"],
        "http://127.0.0.1:3000/oauth/revoke"
    );
    assert_eq!(
        configuration["token_endpoint_auth_methods_supported"],
        serde_json::json!(["client_secret_basic", "client_secret_post", "none"])
    );
    assert_eq!(
        configuration["prompt_values_supported"],
        serde_json::json!(["login", "none", "consent", "select_account"])
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn openid_configuration_allows_newapi_origin() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header("origin", "https://zd.chenl.ing")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("*")
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn jwks_endpoint_returns_a_key_set_document() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn jwks_endpoint_sets_public_cache_control_with_must_revalidate() {
    // Issue #430：JWKS 必须可被共享缓存 60 秒，过期后必须重新验证。
    // must-revalidate 阻止缓存在回源失败时返回陈旧公钥——陈旧公钥会让新签发的
    // 令牌验签失败。
    let (router, key_directory) = test_router().await;
    let (headers, _body) = jwks_response(router).await;

    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("public, max-age=60, must-revalidate")
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn jwks_endpoint_returns_a_deterministic_strong_etag() {
    // Issue #430：ETag 由 JWKS 字节的 SHA-256 派生，同一公钥集合始终产出同一 ETag。
    // 两次独立请求拿到相同 ETag，且是带双引号的强 ETag。
    let (router, key_directory) = test_router().await;
    let (headers_first, body_first) = jwks_response(router.clone()).await;
    let (headers_second, body_second) = jwks_response(router).await;

    assert_eq!(body_first, body_second, "JWKS body must be stable");
    let etag_first = headers_first
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("first response has ETag");
    let etag_second = headers_second
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("second response has ETag");
    assert_eq!(etag_first, etag_second);
    assert!(
        etag_first.starts_with('"') && etag_first.ends_with('"'),
        "{etag_first}"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn jwks_endpoint_returns_304_when_if_none_match_matches_etag() {
    // Issue #430：RP 用 If-None-Match 发起条件请求，公钥集合未变时返回 304。
    // 304 必须携带 ETag 和 Cache-Control，让 RP 继续缓存。
    let (router, key_directory) = test_router().await;
    let (headers, _body) = jwks_response(router.clone()).await;
    let etag = headers
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("first response has ETag");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .header("if-none-match", etag)
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        response.headers().get("etag").and_then(|v| v.to_str().ok()),
        Some(etag)
    );
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("public, max-age=60, must-revalidate")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("304 body");
    assert!(body.is_empty(), "304 must not carry a body");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn jwks_endpoint_returns_304_for_star_if_none_match() {
    // Issue #430：If-None-Match: * 匹配任何资源状态，必须返回 304。
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .header("if-none-match", "*")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn jwks_endpoint_returns_200_when_if_none_match_does_not_match() {
    // Issue #430：ETag 不匹配时返回完整 200 响应，让 RP 更新缓存。
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .header("if-none-match", "\"stale-etag-value\"")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .is_some()
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn jwks_endpoint_allows_cross_origin_reads_without_credentials() {
    // Issue #430：JWKS 是公开只读元数据，允许任意来源跨域读取。
    // 带 Origin 请求时返回 Access-Control-Allow-Origin: * 和 Vary: Origin。
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .header("origin", "https://relying-party.example.com")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
    assert_eq!(
        response.headers().get("vary").and_then(|v| v.to_str().ok()),
        Some("Origin")
    );
    // Issue #442：ETag 不是 CORS 安全列表头，必须显式暴露，浏览器 JS 才能读取。
    assert_eq!(
        response
            .headers()
            .get("access-control-expose-headers")
            .and_then(|v| v.to_str().ok()),
        Some("ETag")
    );
    assert!(
        response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .is_some(),
        "cross-origin JWKS 200 must carry ETag so JS can cache it"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn jwks_endpoint_omits_cors_headers_when_request_has_no_origin() {
    // Issue #430：无 Origin 请求不返回 ACAO，但必须仍带 Vary: Origin，
    // 否则共享缓存可能把无 CORS 副本交给跨域 RP。
    let (router, key_directory) = test_router().await;
    let (headers, _body) = jwks_response(router).await;
    assert!(headers.get("access-control-allow-origin").is_none());
    assert_eq!(
        headers.get("vary").and_then(|v| v.to_str().ok()),
        Some("Origin")
    );
    // ACEH 不是跨域许可，只声明 ETag 可读；无 Origin 时同样写出，避免缓存变体遗漏。
    assert_eq!(
        headers
            .get("access-control-expose-headers")
            .and_then(|v| v.to_str().ok()),
        Some("ETag")
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn jwks_endpoint_304_response_carries_cors_headers_when_origin_present() {
    // Issue #430：304 响应同样需要 CORS 头，否则跨域 RP 拿不到缓存确认。
    let (router, key_directory) = test_router().await;
    let (headers, _body) = jwks_response(router.clone()).await;
    let etag = headers
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("first response has ETag");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .header("if-none-match", etag)
                .header("origin", "https://relying-party.example.com")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
    assert_eq!(
        response.headers().get("vary").and_then(|v| v.to_str().ok()),
        Some("Origin")
    );
    // Issue #442：304 同样必须暴露 ETag，否则跨域 RP 无法继续发 If-None-Match。
    assert_eq!(
        response
            .headers()
            .get("access-control-expose-headers")
            .and_then(|v| v.to_str().ok()),
        Some("ETag")
    );
    assert_eq!(
        response.headers().get("etag").and_then(|v| v.to_str().ok()),
        Some(etag)
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn discovery_endpoint_allows_cross_origin_reads_without_credentials() {
    // Issue #430：Discovery 与 JWKS 共用同一公开 CORS 策略。
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header("origin", "https://relying-party.example.com")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
    assert_eq!(
        response.headers().get("vary").and_then(|v| v.to_str().ok()),
        Some("Origin")
    );
    // Issue #442：不要把 JWKS 的 ACEH 扩到 Discovery——它没有 ETag。
    assert!(
        response
            .headers()
            .get("access-control-expose-headers")
            .is_none()
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn discovery_endpoint_omits_acao_but_varies_on_origin_when_request_has_no_origin() {
    // Issue #430：与 JWKS 对称——无 Origin 不写 ACAO，但始终 Vary: Origin。
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    assert_eq!(
        response.headers().get("vary").and_then(|v| v.to_str().ok()),
        Some("Origin")
    );
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn registration_endpoint_rejects_invalid_email_after_registration_gate() {
    let (router, key_directory) = test_router().await;
    // 注册闸门先于输入校验：先打开公开注册，非法邮箱才走到 validate_registration。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/settings/registration")
                .header("authorization", "Bearer api-test-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"enabled":true,"email_verification_required":false,"invitation_code_required":false}"#,
                ))
                .expect("enable registration request"),
        )
        .await
        .expect("enable registration response");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"invalid-user","email":"invalid","password":"correct horse battery","display_name":null}"#,
                ))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let _ = std::fs::remove_dir_all(key_directory);
}

/// POST 到管理侧用户创建端点必须落到处理器上。
///
/// 404/405 会说明路由没注册或只挂了 GET；401 才说明请求进了守卫（Issue #133）。
#[tokio::test]
async fn admin_user_creation_endpoint_rejects_unauthenticated_requests() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"newcomer","email":"newcomer@example.com","password":"correct horse battery"}"#,
                ))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 未认证请求在解析请求体前由 AdminWrite 拒绝，不应进入管理侧业务校验。
#[tokio::test]
async fn admin_user_creation_requires_admin_before_parsing_input() {
    let (router, key_directory) = test_router().await;
    for body in [
        r#"{"username":"newcomer","email":"newcomer@example.com","password":"correct horse battery","role":"superuser"}"#,
        r#"{"username":"newcomer","email":"newcomer@example.com","password":"correct horse battery","status":"deleted"}"#,
        // 大小写变体同样不在词表内，避免 handler 悄悄接受 "ACTIVE"。
        r#"{"username":"newcomer","email":"newcomer@example.com","password":"correct horse battery","status":"ACTIVE"}"#,
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("valid request"),
            )
            .await
            .expect("response from router");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
        assert_eq!(error["code"], "login_required");
    }
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn login_endpoint_rejects_invalid_identifier_without_database_call() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"identifier":"ab","password":"password"}"#))
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
    assert_eq!(error["code"], "invalid_credentials");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn unknown_api_wellknown_and_health_paths_return_json_not_found_instead_of_spa_html() {
    let (router, key_directory) = test_router().await;
    for path in [
        "/api/v1/does-not-exist",
        "/.well-known/does-not-exist",
        "/health/does-not-exist",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("response from router");

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.split(';').next().unwrap_or(value)),
            Some("application/json"),
            "{path} content type"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let error: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
        assert_eq!(error["code"], "not_found", "{path} error code");
    }
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn unknown_static_asset_path_returns_not_found() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/assets/does-not-exist.js")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn unknown_frontend_route_returns_spa_html() {
    let (router, key_directory) = test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/some-frontend-route")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    let _ = std::fs::remove_dir_all(key_directory);
}
