use crate::{db_isolation, oauth_flow as key_directory};
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use chenxing_auth::admin::bootstrap_guard::{BOOTSTRAP_ATTEMPT_LIMIT, attempt_scope};
use chenxing_auth::oauth::providers::repository::CreateIdentityError;
use chenxing_auth::oauth::providers::repository::create_user_with_identity;
use chenxing_auth::users::email::EmailAddress;
use chenxing_auth::{api, config::Config, state::AppState};
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use tower::ServiceExt;
use uuid::Uuid;

/// 测试夹具的邮箱构造（Issue #302）。规范化只有一个入口，夹具也走它。
fn email_address(raw: impl AsRef<str>) -> EmailAddress {
    let raw = raw.as_ref();
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("fixture email {raw:?}: {error}"))
}

async fn setup() -> (
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let (router, _state, database, key_directory) = setup_with_state().await;
    (router, database, key_directory)
}

async fn setup_with_state() -> (
    axum::Router,
    AppState,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("bootstrap_invariant", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("bootstrap");
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
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("state");
    (api::router(state.clone()), state, database, key_directory)
}

/// 与本次运行一一对应的测试源地址。
///
/// 引导限流 key（`chenxing:bootstrap:attempt:*`）是全局 Redis key，不受测试
/// schema 隔离保护。用 RFC 3849 的 IPv6 文档前缀拼上随机低位，避免并发或重复
/// 运行踩到彼此的窗口（与 `tests/plans.rs` 的源 QPS 测试同一手法）。
fn unique_test_ip() -> IpAddr {
    let tail = Uuid::new_v4().simple().to_string();
    let groups: Vec<&str> = (0..6).map(|i| &tail[i * 4..i * 4 + 4]).collect();
    format!("2001:db8:{}", groups.join(":"))
        .parse()
        .expect("valid IPv6 test address")
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON")
}

/// 引导相关的全部审计事件（成功与被拒共用同一个 action）。
async fn bootstrap_events(
    database: &chenxing_auth::sqlx::PgPool,
) -> Vec<chenxing_auth::audit::AuditEvent> {
    let (events, _total) = chenxing_auth::audit::AuditService::new(database.clone())
        .query(Some("owner_bootstrap"), None, 100, 0)
        .await
        .expect("audit query");
    events
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
    assert_eq!(json(response).await["code"], "registration_disabled");

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
    assert_eq!(json(response).await["id"], 1);

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
    let body = json(response).await;
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
    assert_eq!(json(response).await["code"], "bootstrap_already_completed");

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

/// Issue #304：引导成功的审计记录必须与 Owner 行同一次提交落库。
///
/// 修复前这条审计由 handler 在提交之后 best-effort 写入，审计数据库抖动就能让
/// 「系统里最高权限账号的诞生」永久无记录。现在成功路径必然带来一条
/// `owner_bootstrap` 审计行，且元数据里没有用户名、邮箱或口令。
#[tokio::test]
async fn owner_bootstrap_success_is_audited_in_the_same_commit() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("owner-{suffix}");
    let email = format!("owner-{suffix}@example.com");
    // 源地址与用户名取自不同的随机源：否则两者共享同一段十六进制串，
    // 「审计里没有用户名」的断言可能被 `source_ip` 里的相同子串意外满足或推翻。
    let source = unique_test_ip();

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .extension(ConnectInfo(SocketAddr::new(source, 41010)))
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": "1234567890"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let owner_id = json(response).await["id"].as_i64().expect("owner id");

    let events = bootstrap_events(&database).await;
    assert_eq!(events.len(), 1, "引导成功必须留下且仅留下一条审计事件");
    let event = &events[0];
    assert_eq!(event.actor_type, "bootstrap");
    assert_eq!(event.actor_id, None, "引导时还没有可归属的用户 actor");
    assert_eq!(event.resource_type, "user");
    assert_eq!(event.resource_id, Some(owner_id.to_string()));
    assert_eq!(event.metadata["result"], "success");
    assert_eq!(event.metadata["role"], "owner");
    // 来源可追溯：「谁抢到了 Owner」必须留在审计里，且是规范化后的地址。
    assert_eq!(event.metadata["source_ip"], source.to_string());

    // 个人数据与凭据都不进审计。
    let serialized = serde_json::to_string(event).expect("event serializes");
    assert!(!serialized.contains(&username), "审计不得记录用户名");
    assert!(!serialized.contains(&email), "审计不得记录邮箱");
    assert!(!serialized.contains("1234567890"), "审计不得记录口令");

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 重复引导是拒绝路径：它有自己的审计事件，且不得伪造一条成功记录。
#[tokio::test]
async fn repeat_owner_bootstrap_is_audited_as_a_denial_not_a_success() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let bootstrap_request = |port: u16| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .extension(ConnectInfo(SocketAddr::new(unique_test_ip(), port)))
            .body(Body::from(
                serde_json::json!({
                    "username": format!("owner-{suffix}"),
                    "email": format!("owner-{suffix}@example.com"),
                    "password": "1234567890"
                })
                .to_string(),
            ))
            .expect("bootstrap request")
    };

    let response = router
        .clone()
        .oneshot(bootstrap_request(41011))
        .await
        .expect("first bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .oneshot(bootstrap_request(41012))
        .await
        .expect("repeat bootstrap response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "bootstrap_already_completed");

    let events = bootstrap_events(&database).await;
    assert_eq!(events.len(), 2, "成功与被拒各留一条审计事件");
    let successes = events
        .iter()
        .filter(|event| event.metadata["result"] == "success")
        .count();
    assert_eq!(successes, 1, "引导成功在一个部署里只能出现一次");
    let denial = events
        .iter()
        .find(|event| event.metadata["result"] == "failure")
        .expect("denial event");
    assert_eq!(denial.metadata["reason"], "already_completed");
    // 拒绝事件不指向任何被创建的资源。
    assert_eq!(denial.resource_id, None);

    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// Issue #304：审计写不进去时，引导必须整体回滚。
///
/// 这是整个改动要消除的那个特殊情况：旧实现会留下「Owner 已创建、审计丢失」的
/// 状态，而且响应仍是 201。现在审计 INSERT 在引导事务内，失败即回滚 ——
/// 没有 Owner、没有审计行、响应是可重试的 503，随后重试可以正常完成引导。
///
/// 制造审计故障的手法是把隔离 schema 里的 `audit_events` 改名：`search_path` 指向
/// 本测试独占的 schema，因此不影响其他测试，也不触碰 `public`。改名而不是 DROP，
/// 因为触发器、索引和序列会随表一起改名，改回来即精确恢复；而 DROP 之后
/// `db::migrate` 不会重建它（迁移版本已记录为已应用）。
#[tokio::test]
async fn owner_bootstrap_rolls_back_when_its_audit_record_cannot_be_written() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    chenxing_auth::sqlx::query("ALTER TABLE audit_events RENAME TO audit_events_unavailable")
        .execute(&database)
        .await
        .expect("hide the audit table inside the isolated schema");

    let bootstrap_request = |port: u16| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .extension(ConnectInfo(SocketAddr::new(unique_test_ip(), port)))
            .body(Body::from(
                serde_json::json!({
                    "username": format!("owner-{suffix}"),
                    "email": format!("owner-{suffix}@example.com"),
                    "password": "1234567890"
                })
                .to_string(),
            ))
            .expect("bootstrap request")
    };

    let response = router
        .clone()
        .oneshot(bootstrap_request(41013))
        .await
        .expect("bootstrap response with a broken audit table");
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "审计不可用时引导必须报可重试的失败，而不是声称创建成功"
    );
    assert_eq!(json(response).await["code"], "audit_unavailable");

    // 关键断言：没有 Owner 被创建，也没有任何用户行残留。
    let user_count: i64 = chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&database)
        .await
        .expect("user count");
    assert_eq!(
        user_count, 0,
        "审计失败必须连带回滚用户创建，否则会留下无审计的 Owner"
    );

    // 恢复审计能力后重试必须成功：上一次失败没有烧掉引导机会。
    chenxing_auth::sqlx::query("ALTER TABLE audit_events_unavailable RENAME TO audit_events")
        .execute(&database)
        .await
        .expect("restore the audit table");
    let response = router
        .oneshot(bootstrap_request(41014))
        .await
        .expect("retry bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let events = bootstrap_events(&database).await;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.metadata["result"] == "success")
            .count(),
        1,
        "重试成功后必须恰好有一条成功审计"
    );

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
        json(response).await["code"],
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
    assert_eq!(json(response).await["initialized"], false);

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
    let hidden = json(response).await;

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
    assert_eq!(hidden, json(unknown).await);

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
    assert_eq!(json(response).await["code"], "bootstrap_rate_limited");

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

#[tokio::test]
async fn external_identity_creation_cannot_consume_id_before_owner_bootstrap() {
    let (_, database, key_directory) = setup().await;
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
    let provider_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO oauth_providers
         (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint, client_id, created_at, updated_at)
         VALUES ('Test', $1, 'https://issuer.example/authorize', 'https://issuer.example/token',
                 'https://issuer.example/userinfo', 'test-client', NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("bootstrap-{suffix}"))
    .fetch_one(&database)
    .await
    .expect("insert provider");

    let result = create_user_with_identity(
        &database,
        provider_id,
        &email_address(format!("external-{suffix}@example.com")),
        Some("External"),
        "external-subject",
        "unusable-hash",
    )
    .await;
    assert!(
        result.is_err(),
        "external identity creation must require Owner bootstrap"
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_providers WHERE id = $1")
        .bind(provider_id)
        .execute(&database)
        .await
        .expect("cleanup provider");
    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn concurrent_external_identity_creation_rejects_duplicate_email() {
    let (_, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_email = format!("owner-{suffix}@example.com");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (id, username, email, canonical_email, password_hash, role, created_at, updated_at)
         OVERRIDING SYSTEM VALUE
         VALUES (1, $1, $2, lower($2), 'test-hash', 'owner', NOW(), NOW())",
    )
    .bind(format!("owner-{suffix}"))
    .bind(owner_email)
    .execute(&database)
    .await
    .expect("insert owner");
    chenxing_auth::sqlx::query("SELECT setval(pg_get_serial_sequence('users', 'id'), 1, true)")
        .execute(&database)
        .await
        .expect("advance users sequence");

    let provider_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO oauth_providers
         (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint, client_id, created_at, updated_at)
         VALUES ('Test', $1, 'https://issuer.example/authorize', 'https://issuer.example/token',
                 'https://issuer.example/userinfo', 'test-client', NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("concurrent-{suffix}"))
    .fetch_one(&database)
    .await
    .expect("insert provider");
    // 同一个邮箱的两种书写：一种带空白与大写，一种是规范形态。两者规范化后
    // 匹配值相同，因此并发建号只能成功一次（Issue #302 让这条由数据库约束保证）。
    let email = email_address(format!("external-{suffix}@example.com"));
    let email_variant = email_address(format!("  EXTERNAL-{suffix}@EXAMPLE.COM  "));

    let (first, second) = tokio::join!(
        create_user_with_identity(
            &database,
            provider_id,
            &email_variant,
            Some("External 1"),
            "external-subject-1",
            "unusable-hash",
        ),
        create_user_with_identity(
            &database,
            provider_id,
            &email,
            Some("External 2"),
            "external-subject-2",
            "unusable-hash",
        ),
    );
    let results = [first, second];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(CreateIdentityError::EmailAlreadyRegistered)))
            .count(),
        1
    );

    // 按匹配值计数：胜者是哪一路由调度决定，两路的展示值不同（一路保留了大写的
    // 本地部分），但匹配值必然相同，因此只有匹配值能给出确定的断言。
    let user_count: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE canonical_email = $1")
            .bind(email.canonical())
            .fetch_one(&database)
            .await
            .expect("count external users");
    assert_eq!(user_count, 1);
    assert_eq!(email.canonical(), email_variant.canonical());
    let identity_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE lower(email) = $1",
    )
    .bind(email.canonical())
    .fetch_one(&database)
    .await
    .expect("count external identities");
    assert_eq!(identity_count, 1);

    chenxing_auth::sqlx::query("DELETE FROM oauth_providers WHERE id = $1")
        .bind(provider_id)
        .execute(&database)
        .await
        .expect("cleanup provider");
    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn concurrent_external_identity_creation_reuses_the_same_identity() {
    let (_, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    chenxing_auth::sqlx::query(
        "INSERT INTO users (id, username, email, canonical_email, password_hash, role, created_at, updated_at)
         OVERRIDING SYSTEM VALUE
         VALUES (1, $1, $2, lower($2), 'test-hash', 'owner', NOW(), NOW())",
    )
    .bind(format!("owner-{suffix}"))
    .bind(format!("owner-{suffix}@example.com"))
    .execute(&database)
    .await
    .expect("insert owner");
    chenxing_auth::sqlx::query("SELECT setval(pg_get_serial_sequence('users', 'id'), 1, true)")
        .execute(&database)
        .await
        .expect("advance users sequence");

    let provider_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO oauth_providers
         (name, slug, authorization_endpoint, token_endpoint, userinfo_endpoint, client_id, created_at, updated_at)
         VALUES ('Test', $1, 'https://issuer.example/authorize', 'https://issuer.example/token',
                 'https://issuer.example/userinfo', 'test-client', NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("same-identity-{suffix}"))
    .fetch_one(&database)
    .await
    .expect("insert provider");
    let email = email_address(format!("external-same-{suffix}@example.com"));

    let (first, second) = tokio::join!(
        create_user_with_identity(
            &database,
            provider_id,
            &email,
            Some("External 1"),
            "same-external-subject",
            "unusable-hash",
        ),
        create_user_with_identity(
            &database,
            provider_id,
            &email,
            Some("External 2"),
            "same-external-subject",
            "unusable-hash",
        ),
    );
    let first_id = first.expect("first external identity creation");
    let second_id = second.expect("second external identity should reuse the binding");
    assert_eq!(first_id, second_id);

    let identity_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE provider_id = $1 AND subject = $2",
    )
    .bind(provider_id)
    .bind("same-external-subject")
    .fetch_one(&database)
    .await
    .expect("count external identities");
    assert_eq!(identity_count, 1);

    chenxing_auth::sqlx::query("DELETE FROM oauth_providers WHERE id = $1")
        .bind(provider_id)
        .execute(&database)
        .await
        .expect("cleanup provider");
    chenxing_auth::sqlx::query("DELETE FROM users")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}
