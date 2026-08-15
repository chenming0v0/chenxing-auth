use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine;
use chenxing_auth::{
    api,
    config::Config,
    sessions::{cookies, domain::Session, store::SessionStore},
    state::AppState,
};
use serde_json::Value;
use sha2::Digest;
use tower::ServiceExt;
use uuid::Uuid;

// 「默认套餐回退」用例需要一个 active 默认套餐；测试显式播种它。
#[path = "support/plan_fixtures.rs"]
mod plan_fixtures;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("admin_ui_api", &database_url).await;
    let key_directory = key_directory::isolated_key_directory("admin-ui");
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
        api::router(
            AppState::new_with_pool(config, database.clone())
                .await
                .expect("state"),
        ),
        database,
        key_directory,
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
    database: &chenxing_auth::sqlx::PgPool,
    redis_url: &str,
    user_id: i64,
) -> (String, String, String) {
    let redis = redis::Client::open(redis_url).expect("Redis");
    let store = SessionStore::with_metadata_and_key(redis, database.clone(), [0; 32]);
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("browser session");
    store
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("save browser session");
    let cookie = format!(
        "{}={}; {}={}",
        cookies::session_cookie_name(false),
        session.token,
        cookies::csrf_cookie_name(false),
        session.csrf_token
    );
    (cookie, session.csrf_token, session.token)
}

#[tokio::test]
async fn owner_can_use_admin_ui_queries_but_normal_user_cannot() {
    let (router, database, key_directory) = setup().await;
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
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json(response).await["code"],
        "email_verification_unavailable"
    );

    let public_registration_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE username = $1 OR email = $2",
    )
    .bind(&username)
    .bind(&email)
    .fetch_one(&database)
    .await
    .expect("check failed public registration");
    assert_eq!(public_registration_count, 0);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer admin-ui-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user = json(response).await;
    let user_id = user["id"].as_i64().expect("admin-created user id");
    assert_eq!(user["role"], "user");

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

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let (user_cookies, _user_csrf, user_token) =
        browser_session(&database, &redis_url, user_id).await;
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
    let (router, database, key_directory) = setup().await;
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
    let body = json(response).await;
    assert_eq!(body["code"], "invalid_pagination");
    assert_eq!(
        body["message"],
        "page must be a positive integer and page_size must be an integer between 1 and 100"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email LIKE 'admin-ui-user-%@example.com'")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_queries_reject_out_of_range_pagination() {
    let (router, database, key_directory) = setup().await;
    for path in [
        "/api/v1/admin/users/query?page=0",
        "/api/v1/admin/clients/query?page_size=0",
        "/api/v1/admin/audit/query?page_size=101",
        "/api/v1/admin/users/query?page=abc",
        "/api/v1/admin/clients/query?page=9223372036854775808",
        "/api/v1/admin/audit/query?page_size=18446744073709551616",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("authorization", "Bearer admin-ui-token")
                    .body(Body::empty())
                    .expect("invalid pagination request"),
            )
            .await
            .expect("invalid pagination response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        let body = json(response).await;
        assert_eq!(body["code"], "invalid_pagination", "{path}");
        assert_eq!(
            body["message"],
            "page must be a positive integer and page_size must be an integer between 1 and 100",
            "{path}"
        );
    }

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email LIKE 'admin-ui-user-%@example.com'")
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_audit_query_pages_beyond_the_previous_two_hundred_event_limit() {
    let (router, database, key_directory) = setup().await;
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

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_user_and_client_queries_filter_and_page_in_the_database() {
    let (router, database, key_directory) = setup().await;
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
            // canonical_email 用 lower(email)：夹具邮箱都是纯 ASCII 且结构合法，
            // 与应用层 canonicalizer 的结果一致。
            "INSERT INTO users
             (username, email, canonical_email, password_hash, role, status, created_at, updated_at)
             VALUES ($1, $2, lower($2), 'test-hash', $3, $4, NOW(), NOW())",
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
                .expect("invalid client query"),
        )
        .await
        .expect("invalid client response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "invalid_pagination");

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
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    // 未挂载 / 已过期的用户回退到 active 默认套餐。这里显式重置并播种当前
    // 隔离 schema 所需的默认套餐，不依赖迁移或其他测试留下的行。
    plan_fixtures::clear_all_plans(&database).await;
    plan_fixtures::seed_default_plan(&database).await;
    let plan_code = format!("query-plan-{suffix}");
    let plan_name = format!("Query Plan {suffix}");
    let plan_id = plan_fixtures::insert_private_plan(&database, &plan_code, &plan_name).await;
    let default_username = format!("query-plan-user-default-{suffix}");
    let assigned_username = format!("query-plan-user-assigned-{suffix}");
    let expired_username = format!("query-plan-user-expired-{suffix}");

    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash)
         VALUES ($1, $2, lower($2), 'test-hash')",
    )
    .bind(&default_username)
    .bind(format!("{default_username}@example.com"))
    .execute(&database)
    .await
    .expect("insert default query user");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, plan_id, plan_expires_at)
         VALUES ($1, $2, lower($2), 'test-hash', $3, NOW() + INTERVAL '1 day')",
    )
    .bind(&assigned_username)
    .bind(format!("{assigned_username}@example.com"))
    .bind(plan_id)
    .execute(&database)
    .await
    .expect("insert assigned query user");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, plan_id, plan_expires_at)
         VALUES ($1, $2, lower($2), 'test-hash', $3, NOW() - INTERVAL '1 minute')",
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
    assert_eq!(default_plan["code"], plan_fixtures::DEFAULT_PLAN_CODE);
    assert!(default_plan["name"].is_string());
    assert_eq!(default_plan["expires_at"], Value::Null);

    let assigned_plan = &user(&assigned_username)["plan"];
    assert_eq!(assigned_plan["id"], plan_id);
    assert_eq!(assigned_plan["code"], plan_code);
    assert_eq!(assigned_plan["name"], plan_name);
    assert!(!assigned_plan["expires_at"].is_null());

    let expired_plan = &user(&expired_username)["plan"];
    assert_eq!(expired_plan["code"], plan_fixtures::DEFAULT_PLAN_CODE);
    assert_eq!(expired_plan["expires_at"], Value::Null);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE username LIKE $1")
        .bind(format!("query-plan-user-%-{suffix}"))
        .execute(&database)
        .await
        .expect("cleanup query plan users");
    plan_fixtures::clear_all_plans(&database).await;
    let _ = std::fs::remove_dir_all(key_directory);
}

/// Issue #289：`admin_me` 拆开「账号不存在」与「数据库故障」后，端到端行为不变。
///
/// 这里守两条对外契约：Owner Cookie → 200 且带 `user_id` / `username`；
/// 用户行被删除后 → 仍然是 401。
///
/// 两条 401/500 的分支判定本身由 `src/admin/ui_handlers_tests.rs` 的纯函数用例
/// 覆盖，而不是这里：`Option<SessionRead>` 提取器已经查过一次档案，因此 handler
/// 内的 `Ok(None)` 和 `Err` 只在提取与 handler 之间的竞态窗口里出现，
/// 集成测试无法稳定构造。
#[tokio::test]
async fn admin_me_session_path_returns_identity_and_keeps_401_for_missing_account() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner_username = format!("admin-me-owner-{suffix}");
    let owner_email = format!("admin-me-owner-{suffix}@example.com");
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
                        "password": "correct horse battery"
                    })
                    .to_string(),
                ))
                .expect("owner bootstrap request"),
        )
        .await
        .expect("owner bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let owner_id = json(response).await["id"]
        .as_i64()
        .expect("bootstrapped owner id");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let (owner_cookies, _csrf, owner_token) =
        browser_session(&database, &redis_url, owner_id).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/auth/me")
                .header("cookie", &owner_cookies)
                .body(Body::empty())
                .expect("owner session admin me request"),
        )
        .await
        .expect("owner session admin me response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["user_id"], owner_id);
    assert_eq!(body["username"], owner_username);
    assert_eq!(body["role"], "owner");

    // 删掉用户行但留下 Redis 会话：档案查询返回 Ok(None)，这仍然是 401。
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(owner_id)
        .execute(&database)
        .await
        .expect("delete owner row");
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/auth/me")
                .header("cookie", &owner_cookies)
                .body(Body::empty())
                .expect("deleted owner admin me request"),
        )
        .await
        .expect("deleted owner admin me response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

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
                .encode(sha2::Sha256::digest(owner_token.as_bytes()))
        ),
    )
    .await
    .expect("cleanup session");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn admin_client_registration_rejects_bounded_input_with_stable_bad_request() {
    let (router, _database, key_directory) = setup().await;
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

    let _ = std::fs::remove_dir_all(key_directory);
}
