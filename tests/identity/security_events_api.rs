use std::collections::BTreeSet;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    config::Config,
    sessions::{cookies, domain::Session, store::SessionStore},
    state::AppState,
};
use serde_json::Value;
use tower::ServiceExt;

use crate::{db_isolation, oauth_flow as key_directory};

struct TestApp {
    router: Router,
    database: chenxing_auth::sqlx::PgPool,
    key_directory: std::path::PathBuf,
}

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned())
}

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

async fn setup() -> TestApp {
    let database_url = database_url();
    let redis_url = redis_url();
    let database = db_isolation::isolated_pool("security_events_api", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("security-events-api");
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
    TestApp {
        router: api::router(state),
        database,
        key_directory,
    }
}

async fn seed_user(database: &chenxing_auth::sqlx::PgPool, name: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO users
         (username, email, canonical_email, password_hash, role, status)
         VALUES ($1, $2, lower($2), 'not-a-real-hash', 'user', 'active')
         RETURNING id",
    )
    .bind(name)
    .bind(format!("{name}@example.com"))
    .fetch_one(database)
    .await
    .expect("seed user")
}

async fn browser_session(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> String {
    let redis = redis::Client::open(redis_url()).expect("Redis");
    let store = SessionStore::with_metadata_and_key(redis, database.clone(), [0; 32]);
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("browser session");
    store
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("save browser session");
    format!("{}={}", cookies::session_cookie_name(false), session.token)
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON response")
}

async fn get(router: &Router, uri: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut request = Request::builder().uri(uri);
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    router
        .clone()
        .oneshot(
            request
                .body(Body::empty())
                .expect("security events request"),
        )
        .await
        .expect("security events response")
}

#[tokio::test]
async fn security_events_require_a_session_cookie() {
    let app = setup().await;
    let response = get(&app.router, "/api/v1/auth/security-events", None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(response).await["code"], "login_required");

    let _ = std::fs::remove_dir_all(app.key_directory);
}

#[tokio::test]
async fn security_events_reject_invalid_pagination() {
    let app = setup().await;
    let user_id = seed_user(&app.database, "security-pagination").await;
    let cookie = browser_session(&app.database, user_id).await;

    for query in [
        "page=0",
        "page=-1",
        "page=",
        "page=not-a-number",
        "page_size=0",
        "page_size=101",
        "page=9223372036854775807&page_size=100",
    ] {
        let response = get(
            &app.router,
            &format!("/api/v1/auth/security-events?{query}"),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(
            json(response).await["code"],
            "invalid_pagination",
            "{query}"
        );
    }

    let _ = std::fs::remove_dir_all(app.key_directory);
}

#[tokio::test]
async fn security_events_are_user_scoped_archived_paged_and_whitelisted() {
    let app = setup().await;
    let user_id = seed_user(&app.database, "security-events-owner").await;
    let other_user_id = seed_user(&app.database, "security-events-other").await;
    let cookie = browser_session(&app.database, user_id).await;
    let client_id = "cx_security_events";
    chenxing_auth::sqlx::query(
        "INSERT INTO oauth_clients
         (client_id, client_name, redirect_uris, scopes, auth_method, status, created_at)
         VALUES ($1, 'Security Events Client', '[]'::jsonb, '[]'::jsonb,
                 'none', 'active', NOW())",
    )
    .bind(client_id)
    .execute(&app.database)
    .await
    .expect("seed OAuth client");

    for (actor_user_id, action, resource_type, resource_id, created_at) in [
        (
            other_user_id,
            "other_user_event",
            "oauth_token",
            Some(client_id),
            "2026-01-04T00:00:00Z",
        ),
        (
            user_id,
            "newest_event",
            "oauth_token",
            Some(client_id),
            "2026-01-03T00:00:00Z",
        ),
        (
            user_id,
            "session_event",
            "session",
            Some("sensitive-session-resource"),
            "2026-01-02T00:00:00Z",
        ),
    ] {
        chenxing_auth::sqlx::query(
            "INSERT INTO audit_events
             (actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at)
             VALUES ('user', $1, $2, $3, $4, $5, $6::timestamptz)",
        )
        .bind(actor_user_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(serde_json::json!({"password": "must-not-leak", "result": "success"}))
        .bind(created_at)
        .execute(&app.database)
        .await
        .expect("seed hot audit event");
    }
    chenxing_auth::sqlx::query(
        "INSERT INTO audit_events_archive
         (id, actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at)
         VALUES (9000000001, 'user', $1, 'archived_event', 'oauth_consent', $2,
                 $3, '2026-01-01T00:00:00Z'::timestamptz)",
    )
    .bind(user_id)
    .bind(client_id)
    .bind(serde_json::json!({"token": "must-not-leak"}))
    .execute(&app.database)
    .await
    .expect("seed archived audit event");

    let response = get(
        &app.router,
        "/api/v1/auth/security-events?page=1&page_size=2",
        Some(&cookie),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let first_page = json(response).await;
    assert_eq!(first_page["page"], 1);
    assert_eq!(first_page["page_size"], 2);
    assert_eq!(first_page["total"], 3);
    let items = first_page["items"]
        .as_array()
        .expect("security event items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["action"], "newest_event");
    assert_eq!(items[0]["client_id"], client_id);
    assert_eq!(items[0]["client_name"], "Security Events Client");
    // 未映射的 action 回落到 account/info（Issue #308 分级体系）。
    assert_eq!(items[0]["category"], "account");
    assert_eq!(items[0]["severity"], "info");
    assert_eq!(items[1]["action"], "session_event");
    assert!(items[1]["client_id"].is_null());
    assert!(items[1]["client_name"].is_null());

    let expected_fields = BTreeSet::from([
        "action",
        "category",
        "client_id",
        "client_name",
        "created_at",
        "id",
        "resource_type",
        "severity",
    ]);
    for item in items {
        let fields = item
            .as_object()
            .expect("security event object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(fields, expected_fields);
    }

    let response = get(
        &app.router,
        "/api/v1/auth/security-events?page=2&page_size=2",
        Some(&cookie),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let second_page = json(response).await;
    assert_eq!(second_page["total"], 3);
    assert_eq!(
        second_page["items"].as_array().expect("archive page").len(),
        1
    );
    assert_eq!(second_page["items"][0]["action"], "archived_event");
    assert_eq!(second_page["items"][0]["client_id"], client_id);
    assert_ne!(second_page["items"][0]["action"], "other_user_event");

    let _ = std::fs::remove_dir_all(app.key_directory);
}

/// 详情接口只认「当前 session 用户 + 事件归属」两个条件，未登录一律 401。
#[tokio::test]
async fn security_event_detail_requires_a_session_cookie() {
    let app = setup().await;
    let response = get(&app.router, "/api/v1/auth/security-events/1", None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(response).await["code"], "login_required");

    let _ = std::fs::remove_dir_all(app.key_directory);
}

/// 详情接口：自己的事件返回完整白名单字段；别人的事件、不存在的事件、非法 id
/// 一律 404，不区分「查不到」与「不是你的」，避免事件 id 被当成枚举探测面。
#[tokio::test]
async fn security_event_detail_is_user_scoped_and_not_found_is_indistinguishable() {
    let app = setup().await;
    let user_id = seed_user(&app.database, "security-detail-owner").await;
    let other_user_id = seed_user(&app.database, "security-detail-other").await;
    let cookie = browser_session(&app.database, user_id).await;
    let client_id = "cx_security_detail";
    chenxing_auth::sqlx::query(
        "INSERT INTO oauth_clients
         (client_id, client_name, redirect_uris, scopes, auth_method, status, created_at)
         VALUES ($1, 'Security Detail Client', '[]'::jsonb, '[]'::jsonb,
                 'none', 'active', NOW())",
    )
    .bind(client_id)
    .execute(&app.database)
    .await
    .expect("seed OAuth client");

    let own_event_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO audit_events
         (actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at)
         VALUES ('user', $1, 'oauth_consent', 'oauth_client', $2, $3, NOW())
         RETURNING id",
    )
    .bind(user_id)
    .bind(client_id)
    .bind(serde_json::json!({
        "result": "success",
        "source_ip": "203.0.113.42",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "password": "must-not-leak",
    }))
    .fetch_one(&app.database)
    .await
    .expect("seed own audit event");
    let other_event_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO audit_events
         (actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at)
         VALUES ('user', $1, 'login', 'session', NULL, '{}'::jsonb, NOW())
         RETURNING id",
    )
    .bind(other_user_id)
    .fetch_one(&app.database)
    .await
    .expect("seed other user audit event");
    chenxing_auth::sqlx::query(
        "INSERT INTO audit_events_archive
         (id, actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at)
         VALUES (9000000002, 'user', $1, 'login', 'session', NULL, $2, '2026-01-01T00:00:00Z'::timestamptz)",
    )
    .bind(user_id)
    .bind(serde_json::json!({"result": "success", "source_ip": "198.51.100.7"}))
    .execute(&app.database)
    .await
    .expect("seed archived audit event");

    // 自己的事件：完整字段集 + 白名单请求上下文 + 分级映射 + Client 摘要
    let response = get(
        &app.router,
        &format!("/api/v1/auth/security-events/{own_event_id}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let detail = json(response).await;
    let expected_fields = BTreeSet::from([
        "action",
        "category",
        "client",
        "created_at",
        "id",
        "ip",
        "ip_location",
        "ray_id",
        "resource_type",
        "severity",
        "user_agent",
    ]);
    assert_eq!(
        detail
            .as_object()
            .expect("detail object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected_fields
    );
    assert_eq!(detail["id"], own_event_id);
    assert_eq!(detail["action"], "oauth_consent");
    assert_eq!(detail["category"], "authorization");
    assert_eq!(detail["severity"], "notice");
    assert_eq!(detail["resource_type"], "oauth_client");
    assert_eq!(detail["ip"], "203.0.113.42");
    assert_eq!(detail["user_agent"], "Mozilla/5.0 (X11; Linux x86_64)");
    assert!(detail["ip_location"].is_null());
    assert!(detail["ray_id"].is_null());
    assert!(detail.get("metadata").is_none(), "metadata 原文不得透出");
    assert!(
        !detail.to_string().contains("must-not-leak"),
        "敏感 metadata 值不得出现在详情响应"
    );
    let client = &detail["client"];
    assert_eq!(client["client_id"], client_id);
    assert_eq!(client["client_name"], "Security Detail Client");
    assert_eq!(client["status"], "active");
    assert!(client["created_at"].is_string());

    // 归档事件同样可查
    let response = get(
        &app.router,
        "/api/v1/auth/security-events/9000000002",
        Some(&cookie),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let archived = json(response).await;
    assert_eq!(archived["id"].as_i64(), Some(9000000002));
    assert_eq!(archived["action"], "login");
    assert_eq!(archived["category"], "auth");
    assert_eq!(archived["severity"], "notice");
    assert_eq!(archived["ip"], "198.51.100.7");
    assert!(archived["client"].is_null());

    // 别人的事件、不存在的事件、非法 id：全部 404，响应一致
    for (uri, label) in [
        (
            format!("/api/v1/auth/security-events/{other_event_id}"),
            "other user's event",
        ),
        (
            "/api/v1/auth/security-events/999999999".to_owned(),
            "nonexistent event",
        ),
        ("/api/v1/auth/security-events/-1".to_owned(), "negative id"),
    ] {
        let response = get(&app.router, &uri, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{label}");
        assert_eq!(
            json(response).await["code"],
            "security_event_not_found",
            "{label}"
        );
    }

    let _ = std::fs::remove_dir_all(app.key_directory);
}

/// OAuth 相关事件但 Client 已被删除：`client` 返回 null，前端降级展示，不报错。
#[tokio::test]
async fn security_event_detail_returns_null_client_when_oauth_client_is_deleted() {
    let app = setup().await;
    let user_id = seed_user(&app.database, "security-detail-deleted-client").await;
    let cookie = browser_session(&app.database, user_id).await;
    let event_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO audit_events
         (actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at)
         VALUES ('user', $1, 'consent_revoke', 'oauth_consent', 'cx_gone', '{}'::jsonb, NOW())
         RETURNING id",
    )
    .bind(user_id)
    .fetch_one(&app.database)
    .await
    .expect("seed audit event for deleted client");

    let response = get(
        &app.router,
        &format!("/api/v1/auth/security-events/{event_id}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let detail = json(response).await;
    assert_eq!(detail["action"], "consent_revoke");
    assert_eq!(detail["category"], "authorization");
    assert_eq!(detail["severity"], "warning");
    assert!(detail["client"].is_null());

    let _ = std::fs::remove_dir_all(app.key_directory);
}
