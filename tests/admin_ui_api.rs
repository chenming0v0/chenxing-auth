use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine;
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::sqlx::{Connection, PgConnection};
use chenxing_auth::{
    api,
    config::Config,
    db,
    sessions::{cookies, domain::Session, store::SessionStore},
    state::AppState,
};
use serde_json::Value;
use sha2::Digest;
use tower::ServiceExt;
use uuid::Uuid;

struct SharedDatabaseLock {
    _connection: PgConnection,
}

async fn shared_database_lock(database_url: &str) -> SharedDatabaseLock {
    let mut connection = PgConnection::connect(database_url)
        .await
        .expect("database lock connection");
    chenxing_auth::sqlx::query("BEGIN")
        .execute(&mut connection)
        .await
        .expect("database lock transaction");
    chenxing_auth::sqlx::query("SELECT pg_advisory_xact_lock(hashtext('chenxing-shared-reset'))")
        .execute(&mut connection)
        .await
        .expect("database reset lock");
    SharedDatabaseLock {
        _connection: connection,
    }
}

async fn setup() -> (
    Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    SharedDatabaseLock,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("PostgreSQL");
    db::migrate(&database).await.expect("migrations");
    let lock = shared_database_lock(&database_url).await;
    chenxing_auth::sqlx::query("TRUNCATE users RESTART IDENTITY CASCADE")
        .execute(&database)
        .await
        .expect("reset identity test database");
    let key_directory = std::env::temp_dir().join(format!("chenxing-admin-ui-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "admin-ui-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(AppState::new(config).expect("state")),
        database,
        key_directory,
        lock,
    )
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("JSON")
}

async fn browser_session(
    database_url: &str,
    redis_url: &str,
    user_id: i64,
) -> (String, String, String) {
    let redis = redis::Client::open(redis_url).expect("Redis");
    let store = SessionStore::with_metadata_and_key(
        redis,
        chenxing_auth::sqlx::PgPoolOptions::new()
            .max_connections(2)
            .connect(database_url)
            .await
            .expect("session PostgreSQL"),
        [0; 32],
    );
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("browser session");
    store
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("save browser session");
    let cookie = format!(
        "{}={}; {}={}",
        cookies::SESSION_COOKIE,
        session.token,
        cookies::CSRF_COOKIE,
        session.csrf_token
    );
    (cookie, session.csrf_token, session.token)
}

#[tokio::test]
async fn owner_can_use_admin_ui_queries_but_normal_user_cannot() {
    let (router, database, key_directory, _lock) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_username = format!("admin-ui-owner-{suffix}");
    let owner_email = format!("admin-ui-owner-{suffix}@example.com");
    let username = format!("admin-ui-user-{suffix}");
    let email = format!("admin-ui-user-{suffix}@example.com");
    let password = "correct horse battery";
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": owner_username,
                        "email": owner_email,
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("owner bootstrap request"),
        )
        .await
        .expect("owner bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": username, "email": email, "password": password})
                        .to_string(),
                ))
                .expect("register request"),
        )
        .await
        .expect("register response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user_id = json(response).await["user"]["id"]
        .as_i64()
        .expect("registered user id");

    for uri in [
        "/api/v1/admin/auth/me",
        "/api/v1/admin/overview",
        "/api/v1/admin/users/query?page=1&page_size=10",
        "/api/v1/admin/clients/query?page=1&page_size=10",
        "/api/v1/admin/audit/query?page=1&page_size=10",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", "Bearer admin-ui-token")
                    .body(Body::empty())
                    .expect("admin UI request"),
            )
            .await
            .expect("admin UI response");
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = json(response).await;
        if uri.ends_with("/me") {
            assert_eq!(body["role"], "owner");
        } else if uri.ends_with("overview") {
            assert!(body["users"].is_number());
            assert!(body["oauth_clients"].is_number());
        } else {
            assert!(body["items"].is_array(), "{uri}: {body}");
            assert_eq!(body["page"], 1);
        }
    }

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let (user_cookies, _user_csrf, user_token) =
        browser_session(&database_url, &redis_url, user_id).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/auth/me")
                .header("cookie", &user_cookies)
                .body(Body::empty())
                .expect("normal user admin me request"),
        )
        .await
        .expect("normal user admin me response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users/query?page=1&page_size=10")
                .header("cookie", user_cookies)
                .body(Body::empty())
                .expect("normal user admin request"),
        )
        .await
        .expect("normal user admin response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let redis = redis::Client::open(redis_url).expect("Redis");
    let mut redis_connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: usize = redis::AsyncCommands::del(
        &mut redis_connection,
        format!(
            "chenxing:session:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(user_token.as_bytes()))
        ),
    )
    .await
    .expect("cleanup session");

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(owner_email)
        .execute(&database)
        .await
        .expect("cleanup owner");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_query_rejects_an_offset_that_would_overflow() {
    let (router, database, key_directory, _lock) = setup().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users/query?page=9223372036854775807&page_size=100")
                .header("authorization", "Bearer admin-ui-token")
                .body(Body::empty())
                .expect("overflow query"),
        )
        .await
        .expect("overflow response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email LIKE 'admin-ui-user-%@example.com'")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_audit_query_pages_beyond_the_previous_two_hundred_event_limit() {
    let (router, database, key_directory, _lock) = setup().await;
    let action = format!("page-test-{}", Uuid::new_v4().simple());
    for _ in 0..205 {
        chenxing_auth::sqlx::query(
            "INSERT INTO audit_events
             (actor_type, actor_user_id, action, resource_type, resource_id, metadata, created_at)
             VALUES ('test', NULL, $1, 'test', NULL, '{}'::jsonb, NOW())",
        )
        .bind(&action)
        .execute(&database)
        .await
        .expect("insert audit event");
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/admin/audit/query?page=21&page_size=10&action={action}"
                ))
                .header("authorization", "Bearer admin-ui-token")
                .body(Body::empty())
                .expect("audit page request"),
        )
        .await
        .expect("audit page response");
    assert_eq!(response.status(), StatusCode::OK);
    let page = json(response).await;
    assert_eq!(page["total"], 205);
    assert_eq!(page["items"].as_array().expect("audit items").len(), 5);

    chenxing_auth::sqlx::query("DELETE FROM audit_events WHERE action = $1")
        .bind(&action)
        .execute(&database)
        .await
        .expect("cleanup audit events");
    let _ = std::fs::remove_dir_all(key_directory);
}
