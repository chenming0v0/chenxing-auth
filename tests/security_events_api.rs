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

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

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
        .oneshot(request.body(Body::empty()).expect("security events request"))
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
        assert_eq!(json(response).await["code"], "invalid_pagination", "{query}");
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
    let items = first_page["items"].as_array().expect("security event items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["action"], "newest_event");
    assert_eq!(items[0]["client_id"], client_id);
    assert_eq!(items[0]["client_name"], "Security Events Client");
    assert_eq!(items[1]["action"], "session_event");
    assert!(items[1]["client_id"].is_null());
    assert!(items[1]["client_name"].is_null());

    let expected_fields = BTreeSet::from([
        "action",
        "client_id",
        "client_name",
        "created_at",
        "id",
        "resource_type",
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
    assert_eq!(second_page["items"].as_array().expect("archive page").len(), 1);
    assert_eq!(second_page["items"][0]["action"], "archived_event");
    assert_eq!(second_page["items"][0]["client_id"], client_id);
    assert_ne!(second_page["items"][0]["action"], "other_user_event");

    let _ = std::fs::remove_dir_all(app.key_directory);
}
