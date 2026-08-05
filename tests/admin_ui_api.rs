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
        api::router(AppState::new(config).await.expect("state")),
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

#[tokio::test]
async fn admin_user_and_client_queries_filter_and_page_in_the_database() {
    let (router, database, key_directory, _lock) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let active_username = format!("query-active-{suffix}");
    let disabled_username = format!("query-disabled-{suffix}");
    let other_username = format!("query-other-{suffix}");
    for (username, status, role) in [
        (&active_username, "active", "user"),
        (&disabled_username, "disabled", "user"),
        (&other_username, "active", "admin"),
    ] {
        chenxing_auth::sqlx::query(
            "INSERT INTO users
             (username, email, password_hash, role, status, created_at, updated_at)
             VALUES ($1, $2, 'test-hash', $3, $4, NOW(), NOW())",
        )
        .bind(username)
        .bind(format!("{username}@example.com"))
        .bind(role)
        .bind(status)
        .execute(&database)
        .await
        .expect("insert query user");
    }
    let active_client = format!("query-active-client-{suffix}");
    let disabled_client = format!("query-disabled-client-{suffix}");
    for (client_id, client_name, status) in [
        (
            format!("cx-query-active-{suffix}"),
            active_client.clone(),
            "active",
        ),
        (
            format!("cx-query-disabled-{suffix}"),
            disabled_client.clone(),
            "disabled",
        ),
    ] {
        chenxing_auth::sqlx::query(
            "INSERT INTO oauth_clients
             (client_id, client_name, client_secret_hash, redirect_uris, scopes, status, created_at)
             VALUES ($1, $2, 'test-hash', $3, $4, $5, NOW())",
        )
        .bind(client_id)
        .bind(client_name)
        .bind(serde_json::json!(["https://query.example/callback"]))
        .bind(serde_json::json!(["openid"]))
        .bind(status)
        .execute(&database)
        .await
        .expect("insert query client");
    }

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/admin/users/query?page=1&page_size=1&search={active_username}&status=active"
                ))
                .header("authorization", "Bearer admin-ui-token")
                .body(Body::empty())
                .expect("filtered user query"),
        )
        .await
        .expect("filtered user response");
    assert_eq!(response.status(), StatusCode::OK);
    let users = json(response).await;
    assert_eq!(users["total"], 1);
    assert_eq!(users["items"].as_array().expect("user items").len(), 1);
    assert_eq!(users["items"][0]["username"], active_username);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/admin/users/query?page=2&page_size=1&search={active_username}"
                ))
                .header("authorization", "Bearer admin-ui-token")
                .body(Body::empty())
                .expect("empty user page query"),
        )
        .await
        .expect("empty user page response");
    let empty_page = json(response).await;
    assert_eq!(empty_page["page"], 2);
    assert_eq!(empty_page["page_size"], 1);
    assert_eq!(empty_page["total"], 1);
    assert!(
        empty_page["items"]
            .as_array()
            .expect("empty items")
            .is_empty()
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/admin/clients/query?page=1&page_size=1&search={disabled_client}&status=disabled"
                ))
                .header("authorization", "Bearer admin-ui-token")
                .body(Body::empty())
                .expect("filtered client query"),
        )
        .await
        .expect("filtered client response");
    let clients = json(response).await;
    assert_eq!(clients["total"], 1);
    assert_eq!(clients["items"][0]["client_name"], disabled_client);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/clients/query?page=1&page_size=1000")
                .header("authorization", "Bearer admin-ui-token")
                .body(Body::empty())
                .expect("clamped client query"),
        )
        .await
        .expect("clamped client response");
    let clamped = json(response).await;
    assert_eq!(clamped["page_size"], 100);
    assert_eq!(clamped["total"], 2);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE username LIKE $1")
        .bind(format!("query-%-{suffix}"))
        .execute(&database)
        .await
        .expect("cleanup query users");
    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id LIKE $1")
        .bind(format!("cx-query-%-{suffix}"))
        .execute(&database)
        .await
        .expect("cleanup query clients");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_user_query_returns_effective_plan_and_hides_expired_assignment() {
    let (router, database, key_directory, _lock) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let plan_code = format!("query-plan-{suffix}");
    let plan_name = format!("Query Plan {suffix}");
    let plan_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO plans (code, name, is_default, status)
         VALUES ($1, $2, FALSE, 'active')
         RETURNING id",
    )
    .bind(&plan_code)
    .bind(&plan_name)
    .fetch_one(&database)
    .await
    .expect("insert query plan");
    let default_username = format!("query-plan-user-default-{suffix}");
    let assigned_username = format!("query-plan-user-assigned-{suffix}");
    let expired_username = format!("query-plan-user-expired-{suffix}");

    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, password_hash)
         VALUES ($1, $2, 'test-hash')",
    )
    .bind(&default_username)
    .bind(format!("{default_username}@example.com"))
    .execute(&database)
    .await
    .expect("insert default query user");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, password_hash, plan_id, plan_expires_at)
         VALUES ($1, $2, 'test-hash', $3, NOW() + INTERVAL '1 day')",
    )
    .bind(&assigned_username)
    .bind(format!("{assigned_username}@example.com"))
    .bind(plan_id)
    .execute(&database)
    .await
    .expect("insert assigned query user");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, password_hash, plan_id, plan_expires_at)
         VALUES ($1, $2, 'test-hash', $3, NOW() - INTERVAL '1 minute')",
    )
    .bind(&expired_username)
    .bind(format!("{expired_username}@example.com"))
    .bind(plan_id)
    .execute(&database)
    .await
    .expect("insert expired query user");

    let response = router
        .oneshot(
            Request::builder()
                .uri(
                    "/api/v1/admin/users/query?page=1&page_size=100&search=query-plan-user-"
                        .to_string(),
                )
                .header("authorization", "Bearer admin-ui-token")
                .body(Body::empty())
                .expect("effective plan query request"),
        )
        .await
        .expect("effective plan query response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    let items = body["items"].as_array().expect("query items");
    let user = |username: &str| {
        items
            .iter()
            .find(|item| item["username"] == username)
            .unwrap_or_else(|| panic!("missing user {username}"))
    };

    let default_plan = &user(&default_username)["plan"];
    assert!(default_plan["id"].is_i64());
    assert_eq!(default_plan["code"], "basic");
    assert!(default_plan["name"].is_string());
    assert_eq!(default_plan["expires_at"], Value::Null);

    let assigned_plan = &user(&assigned_username)["plan"];
    assert_eq!(assigned_plan["id"], plan_id);
    assert_eq!(assigned_plan["code"], plan_code);
    assert_eq!(assigned_plan["name"], plan_name);
    assert!(!assigned_plan["expires_at"].is_null());

    let expired_plan = &user(&expired_username)["plan"];
    assert_eq!(expired_plan["code"], "basic");
    assert_eq!(expired_plan["expires_at"], Value::Null);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE username LIKE $1")
        .bind(format!("query-plan-user-%-{suffix}"))
        .execute(&database)
        .await
        .expect("cleanup query plan users");
    chenxing_auth::sqlx::query("DELETE FROM plans WHERE id = $1")
        .bind(plan_id)
        .execute(&database)
        .await
        .expect("cleanup query plan");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_client_registration_rejects_bounded_input_with_stable_bad_request() {
    let (router, database, key_directory, _lock) = setup().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer admin-ui-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "bounded client",
                        "redirect_uris": (0..11)
                            .map(|index| format!("https://bounded-{index}.example/callback"))
                            .collect::<Vec<_>>(),
                        "scopes": ["openid"]
                    })
                    .to_string(),
                ))
                .expect("bounded admin client request"),
        )
        .await
        .expect("bounded admin client response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "invalid_client_registration");

    chenxing_auth::sqlx::query("TRUNCATE users RESTART IDENTITY CASCADE")
        .execute(&database)
        .await
        .expect("cleanup bounded client data");
    let _ = std::fs::remove_dir_all(key_directory);
}
