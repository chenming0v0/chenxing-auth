use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use chenxing_auth::admin::bootstrap_guard::{BOOTSTRAP_ATTEMPT_LIMIT, attempt_scope};
use chenxing_auth::state::AppState;
use chenxing_auth::users::email::EmailAddress;
use std::net::{IpAddr, SocketAddr};
use tower::ServiceExt;
use uuid::Uuid;

use crate::http;

/// 测试夹具的邮箱构造（Issue #302）。规范化只有一个入口，夹具也走它。
pub(super) fn email_address(raw: impl AsRef<str>) -> EmailAddress {
    let raw = raw.as_ref();
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("fixture email {raw:?}: {error}"))
}

pub(super) async fn setup() -> (
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let (router, _state, database, key_directory) = setup_with_state().await;
    (router, database, key_directory)
}

pub(super) async fn setup_with_state() -> (
    axum::Router,
    AppState,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let harness = crate::harness::HarnessBuilder::new("bootstrap_invariant")
        .admin_token("")
        .build()
        .await;
    (
        harness.router,
        harness.state,
        harness.database,
        harness.key_directory,
    )
}

/// 与本次运行一一对应的测试源地址。
///
/// 引导限流 key（`chenxing:bootstrap:attempt:*`）是全局 Redis key，不受测试
/// schema 隔离保护。用 RFC 3849 的 IPv6 文档前缀拼上随机低位，避免并发或重复
/// 运行踩到彼此的窗口（与 `tests/plans.rs` 的源 QPS 测试同一手法）。
pub(super) fn unique_test_ip() -> IpAddr {
    let tail = Uuid::new_v4().simple().to_string();
    let groups: Vec<&str> = (0..6).map(|i| &tail[i * 4..i * 4 + 4]).collect();
    format!("2001:db8:{}", groups.join(":"))
        .parse()
        .expect("valid IPv6 test address")
}

#[tokio::test]
async fn public_registration_cannot_consume_id_before_owner_bootstrap() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("user-{suffix}"),
                        "email": format!("user-{suffix}@example.com"),
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        http::json_body(response).await["code"],
        "registration_disabled"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("owner-{suffix}"),
                        "email": format!("owner-{suffix}@example.com"),
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(http::json_body(response).await["id"], 1);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owner_bootstrap_returns_the_inserted_profile_and_rejects_repeat_calls() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("owner-{suffix}");
    let email = format!("owner-{suffix}@example.com");

    let bootstrap_request = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "username": username,
                    "email": email,
                    "password": "1234567890"
                })
                .to_string(),
            ))
            .expect("bootstrap request")
    };

    // 首次初始化必须返回事务内回查到的完整 Owner profile，而不是 panic 或空响应。
    let response = router
        .clone()
        .oneshot(bootstrap_request())
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = http::json_body(response).await;
    assert_eq!(body["id"], 1);
    assert_eq!(body["username"], username);
    assert_eq!(body["email"], email);
    assert_eq!(body["role"], "owner");

    // 回查发生在事务内，因此这里返回的 profile 必须与库中持久化的行一致。
    let (stored_username, stored_status, stored_role): (String, String, String) =
        chenxing_auth::sqlx::query_as("SELECT username, status, role FROM users WHERE id = 1")
            .fetch_one(&database)
            .await
            .expect("stored owner row");
    assert_eq!(stored_username, username);
    assert_eq!(stored_status, "active");
    assert_eq!(stored_role, "owner");

    // 重复调用仍然被 Owner 唯一性不变量拒绝。
    let response = router
        .oneshot(bootstrap_request())
        .await
        .expect("repeat bootstrap response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        http::json_body(response).await["code"],
        "bootstrap_already_completed"
    );

    let owner_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'owner'")
            .fetch_one(&database)
            .await
            .expect("owner count");
    assert_eq!(owner_count, 1);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owner_bootstrap_rejects_a_non_empty_database_without_an_owner() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, created_at, updated_at)
         VALUES ($1, $2, lower($2), 'test-hash', NOW(), NOW())",
    )
    .bind(format!("existing-{suffix}"))
    .bind(format!("existing-{suffix}@example.com"))
    .execute(&database)
    .await
    .expect("insert existing user");

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("owner-{suffix}"),
                        "email": format!("owner-{suffix}@example.com"),
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        http::json_body(response).await["code"],
        "owner_bootstrap_requires_empty_database"
    );

    let owner_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'owner'")
            .fetch_one(&database)
            .await
            .expect("owner count");
    assert_eq!(owner_count, 0);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// #279：状态端点在已初始化后不得向匿名调用者确认「这是一台已初始化的实例」。
///
/// 未初始化时必须如实返回 `initialized: false`（初始化页面依赖它），初始化完成后
/// 必须退化为与未注册路由逐字节一致的 404，扫描器无法据此筛出可抢注的实例。
#[tokio::test]
async fn bootstrap_status_stops_answering_once_the_owner_exists() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();

    let status_request = || {
        Request::builder()
            .uri("/api/v1/admin/bootstrap/status")
            .extension(ConnectInfo(SocketAddr::new(unique_test_ip(), 41000)))
            .body(Body::empty())
            .expect("bootstrap status request")
    };

    let response = router
        .clone()
        .oneshot(status_request())
        .await
        .expect("uninitialized status response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(http::json_body(response).await["initialized"], false);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .extension(ConnectInfo(SocketAddr::new(unique_test_ip(), 41001)))
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("owner-{suffix}"),
                        "email": format!("owner-{suffix}@example.com"),
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(status_request())
        .await
        .expect("initialized status response");
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "an initialized instance must not confirm its bootstrap state to anonymous callers"
    );
    let hidden = http::json_body(response).await;

    // 响应体必须与任意未注册路径完全一致，否则差异本身就是预言机。
    let unknown = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/bootstrap/does-not-exist")
                .body(Body::empty())
                .expect("unknown path request"),
        )
        .await
        .expect("unknown path response");
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(hidden, http::json_body(unknown).await);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 浏览器 HTML 导航由后端直接完成首屏引导，不再让生产 SPA 用预期的 404 探测初始化状态。
#[tokio::test]
async fn html_navigation_keeps_bootstrap_redirects_without_status_probe() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();

    let html_navigation = |path: &str| {
        Request::builder()
            .method("GET")
            .uri(path)
            .header("accept", "text/html,application/xhtml+xml")
            .header("sec-fetch-dest", "document")
            .body(Body::empty())
            .expect("HTML navigation request")
    };

    let response = router
        .clone()
        .oneshot(html_navigation("/login"))
        .await
        .expect("uninitialized login navigation response");
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(response.headers().get("location").unwrap(), "/bootstrap");

    let response = router
        .clone()
        .oneshot(html_navigation("/bootstrap"))
        .await
        .expect("uninitialized bootstrap navigation response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .extension(ConnectInfo(SocketAddr::new(unique_test_ip(), 41004)))
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("owner-{suffix}"),
                        "email": format!("owner-{suffix}@example.com"),
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(html_navigation("/bootstrap"))
        .await
        .expect("initialized bootstrap navigation response");
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(response.headers().get("location").unwrap(), "/login");

    let response = router
        .oneshot(html_navigation("/login"))
        .await
        .expect("initialized login navigation response");
    assert_eq!(response.status(), StatusCode::OK);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// #279：引导 POST 必须受按源 IP 的滑动窗口配额约束。
///
/// 直接饱和 Redis 窗口而不是连发 HTTP：走 HTTP 打满配额要付
/// `BOOTSTRAP_ATTEMPT_LIMIT` 次 Argon2（每次 19 MiB 内存），而这里要验证的是
/// handler 是否真的调用了限流器。如果有人删掉 `enforce_bootstrap_attempt_limit`，
/// 请求会进入业务逻辑并返回 201，测试失败。
#[tokio::test]
async fn owner_bootstrap_is_rate_limited_per_source_ip() {
    let (router, state, database, key_directory) = setup_with_state().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let source = unique_test_ip();
    let scope = attempt_scope(&source.to_string());

    for _ in 0..BOOTSTRAP_ATTEMPT_LIMIT {
        assert!(
            state
                .qps
                .allow_scoped(
                    &scope,
                    BOOTSTRAP_ATTEMPT_LIMIT,
                    chenxing_auth::admin::bootstrap_guard::BOOTSTRAP_ATTEMPT_WINDOW_MS,
                )
                .await
                .expect("pre-saturate bootstrap window"),
            "pre-saturation must stay inside the configured budget"
        );
    }

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .extension(ConnectInfo(SocketAddr::new(source, 41002)))
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("owner-{suffix}"),
                        "email": format!("owner-{suffix}@example.com"),
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("rate limited bootstrap request"),
        )
        .await
        .expect("rate limited bootstrap response");
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the bootstrap endpoint must enforce a per-source attempt budget"
    );
    assert_eq!(
        http::json_body(response).await["code"],
        "bootstrap_rate_limited"
    );

    // 被限流的请求不得写库：Owner 仍然不存在，合法管理员的引导窗口没有被烧掉。
    let owner_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'owner'")
            .fetch_one(&database)
            .await
            .expect("owner count");
    assert_eq!(owner_count, 0);

    // 另一个源 IP 的配额独立，限流不会把整台实例锁死在未初始化状态。
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .extension(ConnectInfo(SocketAddr::new(unique_test_ip(), 41003)))
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("owner-{suffix}"),
                        "email": format!("owner-{suffix}@example.com"),
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("fresh source bootstrap request"),
        )
        .await
        .expect("fresh source bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}
