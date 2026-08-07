use axum::{
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
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

async fn setup() -> (
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("admin_api", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-admin-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "bootstrap-admin-token".to_owned();
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
) -> (String, String) {
    let redis = redis::Client::open(redis_url).expect("session Redis");
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
    (cookie, session.csrf_token)
}

#[tokio::test]
async fn bootstrap_admin_can_login_and_use_cookie_session() {
    let (router, database, key_directory) = setup().await;
    let username = format!("admin-{}", Uuid::new_v4().simple());
    let email = format!("{username}@example.com");
    let password = "1234567890";

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/bootstrap/status")
                .body(Body::empty())
                .expect("bootstrap status request"),
        )
        .await
        .expect("bootstrap status response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await["initialized"], false);

    let contender = format!("contender-{}", Uuid::new_v4().simple());
    let contender_email = format!("{contender}@example.com");
    let first_request = router.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"username": username, "email": email, "password": password})
                    .to_string(),
            ))
            .expect("first bootstrap request"),
    );
    let second_request = router.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"username": contender, "email": contender_email, "password": password})
                    .to_string(),
            ))
            .expect("second concurrent bootstrap request"),
    );
    let (first_response, second_response) = tokio::join!(first_request, second_request);
    let first_response = first_response.expect("first bootstrap response");
    let second_response = second_response.expect("second bootstrap response");
    assert!(
        (first_response.status() == StatusCode::CREATED
            && second_response.status() == StatusCode::CONFLICT)
            || (first_response.status() == StatusCode::CONFLICT
                && second_response.status() == StatusCode::CREATED),
        "bootstrap statuses: {} and {}",
        first_response.status(),
        second_response.status()
    );
    let username = if first_response.status() == StatusCode::CREATED {
        let response = json(first_response).await;
        assert_eq!(response["id"], 1);
        assert_eq!(response["role"], "owner");
        username
    } else {
        let response = json(second_response).await;
        assert_eq!(response["id"], 1);
        assert_eq!(response["role"], "owner");
        contender.clone()
    };

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/bootstrap/status")
                .body(Body::empty())
                .expect("initialized status request"),
        )
        .await
        .expect("initialized status response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await["initialized"], true);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/audit")
                .header("authorization", "Bearer bootstrap-admin-token")
                .body(Body::empty())
                .expect("audit request"),
        )
        .await
        .expect("audit response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(json(response).await.is_array());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/admins")
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("operator-{username}"),
                        "email": format!("operator-{username}@example.com"),
                        "password": password,
                        "role": "admin"
                    })
                    .to_string(),
                ))
                .expect("create admin request"),
        )
        .await
        .expect("create admin response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/admins")
                .header("authorization", "Bearer bootstrap-admin-token")
                .body(Body::empty())
                .expect("list admins request"),
        )
        .await
        .expect("list admins response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        json(response)
            .await
            .as_array()
            .is_some_and(|admins| admins.len() >= 2)
    );

    let user_email = format!("managed-{username}@example.com");
    let user_username = format!("managed-{username}");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": user_username, "email": user_email, "password": password}).to_string(),
                ))
                .expect("user registration request"),
        )
        .await
        .expect("user registration response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(response).await["code"], "email_verification_unavailable");

    let public_registration_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE username = $1 OR email = $2",
    )
    .bind(&user_username)
    .bind(&user_email)
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
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": user_username,
                        "email": user_email,
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
    let user_id = user["id"].as_i64().expect("numeric user id");
    assert_eq!(user["role"], "user");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer bootstrap-admin-token")
                .body(Body::empty())
                .expect("list users request"),
        )
        .await
        .expect("list users response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        json(response)
            .await
            .as_array()
            .is_some_and(|users| users.iter().any(|user| user["id"] == user_id))
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/disabled"))
                .header("authorization", "Bearer bootstrap-admin-token")
                .body(Body::empty())
                .expect("disable user request"),
        )
        .await
        .expect("disable user response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": format!("second-{username}"), "email": "invalid", "password": password})
                        .to_string(),
                ))
                .expect("second bootstrap request"),
        )
        .await
        .expect("second bootstrap response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE username IN ($1, $2, $3)")
        .bind(&username)
        .bind(&contender)
        .bind(format!("operator-{username}"))
        .execute(&database)
        .await
        .expect("cleanup privileged users");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(&user_email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn owner_role_mutation_is_owner_only_and_updates_existing_sessions() {
    let (router, database, key_directory) = setup().await;
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("owner-{suffix}");
    let owner_email = format!("{owner}@example.com");
    let password = "1234567890";

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": owner, "email": owner_email, "password": password}).to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let create_user = |username: String, email: String| {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/admins")
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": username, "email": email, "password": password, "role": "admin"}).to_string(),
                ))
                .expect("create privileged user request"),
        )
    };
    let response = create_user(
        format!("managed-{suffix}"),
        format!("managed-{suffix}@example.com"),
    )
    .await
    .expect("create privileged user response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let managed_id = json(response).await["id"]
        .as_i64()
        .expect("managed user id");

    let (managed_cookie, managed_csrf) = browser_session(&database, &redis_url, managed_id).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("cookie", &managed_cookie)
                .body(Body::empty())
                .expect("managed session request"),
        )
        .await
        .expect("managed session response");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{managed_id}/role"))
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "user"}).to_string()))
                .expect("role mutation request"),
        )
        .await
        .expect("role mutation response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("cookie", &managed_cookie)
                .body(Body::empty())
                .expect("demoted session request"),
        )
        .await
        .expect("demoted session response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (owner_cookie, owner_csrf) = browser_session(&database, &redis_url, 1).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users/1/role")
                .header("cookie", &owner_cookie)
                .header("x-csrf-token", owner_csrf)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "admin"}).to_string()))
                .expect("self role mutation request"),
        )
        .await
        .expect("self role mutation response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = create_user(
        format!("second-owner-{suffix}"),
        format!("second-owner-{suffix}@example.com"),
    )
    .await
    .expect("create second owner response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let second_admin_id = json(response).await["id"]
        .as_i64()
        .expect("second admin id");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{second_admin_id}/role"))
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "owner"}).to_string()))
                .expect("promote second owner request"),
        )
        .await
        .expect("promote second owner response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users/1/role")
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "admin"}).to_string()))
                .expect("demote first owner request"),
        )
        .await
        .expect("demote first owner response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{second_admin_id}/role"))
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"role": "admin"}).to_string()))
                .expect("demote last owner request"),
        )
        .await
        .expect("demote last owner response");
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let _ = managed_csrf;
    let _ = database;
    let _ = std::fs::remove_dir_all(key_directory);
}

/// `POST /api/v1/admin/users`（Issue #133）。
///
/// 覆盖三件事：成功路径返回落库后的 PublicUser 且不含任何凭据材料、
/// 输入错误落到 400/409 而不是 500、提升角色时权限被抬到 ManageRoles。
#[tokio::test]
async fn admin_user_creation_covers_success_validation_and_role_escalation() {
    let (router, database, key_directory) = setup().await;
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let suffix = Uuid::new_v4().simple().to_string();
    let password = "1234567890";

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
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let create = |body: serde_json::Value| {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("create user request"),
        )
    };

    // 默认角色与状态：不传 role/status 时必须落成最低权限的活跃账号。
    let response = create(serde_json::json!({
        "username": format!("managed-{suffix}"),
        "email": format!("managed-{suffix}@example.com"),
        "password": password
    }))
    .await
    .expect("create default user response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json(response).await;
    assert_eq!(created["role"], "user");
    assert_eq!(created["status"], "active");
    assert_eq!(created["username"], format!("managed-{suffix}"));
    // display_name 缺省保持 NULL，不回填 username。
    assert!(created["display_name"].is_null());
    assert!(created["id"].as_i64().is_some());
    // 响应不得包含任何凭据材料。
    assert!(created.get("password").is_none());
    assert!(created.get("password_hash").is_none());

    // 显式 disabled 状态必须落库，而不是被忽略成 active。
    let response = create(serde_json::json!({
        "username": format!("suspended-{suffix}"),
        "email": format!("suspended-{suffix}@example.com"),
        "password": password,
        "display_name": "  ",
        "status": "disabled"
    }))
    .await
    .expect("create disabled user response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json(response).await;
    assert_eq!(created["status"], "disabled");
    // 空白 display_name 被 trim 成 NULL。
    assert!(created["display_name"].is_null());

    // 输入错误必须是 400，重复用户名/邮箱必须是 409。
    for (body, status, code) in [
        (
            serde_json::json!({
                "username": format!("badmail-{suffix}"),
                "email": "invalid",
                "password": password
            }),
            StatusCode::BAD_REQUEST,
            "invalid_email",
        ),
        (
            serde_json::json!({
                "username": format!("shortpass-{suffix}"),
                "email": format!("shortpass-{suffix}@example.com"),
                "password": "short"
            }),
            StatusCode::BAD_REQUEST,
            "password_too_short",
        ),
        (
            serde_json::json!({
                "username": "ab",
                "email": format!("baduser-{suffix}@example.com"),
                "password": password
            }),
            StatusCode::BAD_REQUEST,
            "invalid_username",
        ),
        (
            serde_json::json!({
                "username": format!("managed-{suffix}"),
                "email": format!("duplicate-{suffix}@example.com"),
                "password": password
            }),
            StatusCode::CONFLICT,
            "username_already_registered",
        ),
        (
            serde_json::json!({
                "username": format!("duplicate-{suffix}"),
                "email": format!("managed-{suffix}@example.com"),
                "password": password
            }),
            StatusCode::CONFLICT,
            "email_already_registered",
        ),
    ] {
        let response = create(body).await.expect("create user error response");
        assert_eq!(response.status(), status, "{code}");
        assert_eq!(json(response).await["code"], code);
    }

    // admin 角色只有 ManageUsers，创建 owner 需要 ManageRoles → 403。
    let response = create(serde_json::json!({
        "username": format!("promoted-{suffix}"),
        "email": format!("promoted-{suffix}@example.com"),
        "password": password,
        "role": "admin"
    }))
    .await
    .expect("create admin response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let admin_id = json(response).await["id"].as_i64().expect("admin id");
    let (admin_cookie, admin_csrf) = browser_session(&database, &redis_url, admin_id).await;

    let escalate = |role: &'static str| {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("cookie", &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("escalated-{role}-{suffix}"),
                        "email": format!("escalated-{role}-{suffix}@example.com"),
                        "password": password,
                        "role": role
                    })
                    .to_string(),
                ))
                .expect("escalation request"),
        )
    };
    for role in ["admin", "owner"] {
        let response = escalate(role).await.expect("escalation response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{role}");
        assert_eq!(json(response).await["code"], "admin_forbidden");
    }

    // 同一个 admin 会话创建普通用户是允许的：ManageUsers 就够了。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("cookie", &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("by-admin-{suffix}"),
                        "email": format!("by-admin-{suffix}@example.com"),
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("admin session create request"),
        )
        .await
        .expect("admin session create response");
    assert_eq!(response.status(), StatusCode::CREATED);

    // 缺少 X-CSRF-Token 的 Cookie 会话写操作必须被 CSRF 校验拦下。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("no-csrf-{suffix}"),
                        "email": format!("no-csrf-{suffix}@example.com"),
                        "password": password
                    })
                    .to_string(),
                ))
                .expect("missing CSRF request"),
        )
        .await
        .expect("missing CSRF response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "csrf_invalid");

    chenxing_auth::sqlx::query("DELETE FROM users WHERE username LIKE '%' || $1::text")
        .bind(&suffix)
        .execute(&database)
        .await
        .expect("cleanup created users");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn list_users_enforces_server_side_limit() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();

    // 直接批量插入，避免 Argon2 哈希让测试变慢；password_hash 不参与本用例校验。
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, password_hash, role, status)
         SELECT 'bulk-' || $1::text || '-' || series.i,
                'bulk-' || $1::text || '-' || series.i || '@example.com',
                'unused-hash',
                'user',
                'active'
         FROM generate_series(1, 260) AS series(i)",
    )
    .bind(&suffix)
    .execute(&database)
    .await
    .expect("bulk insert users");

    let list = |query: &'static str| {
        let router = router.clone();
        async move {
            let response = router
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/admin/users{query}"))
                        .header("authorization", "Bearer bootstrap-admin-token")
                        .body(Body::empty())
                        .expect("list users request"),
                )
                .await
                .expect("list users response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json(response).await;
            body.as_array().expect("user array").len()
        }
    };

    // 未提供 limit 时使用默认 50，而不是倾倒 260 条。
    assert_eq!(list("").await, 50);
    // 超过上限的 limit 被 clamp 到 200，即使表里有 260 条。
    assert_eq!(list("?limit=300").await, 200);
    assert_eq!(list("?limit=9223372036854775807").await, 200);
    // limit 为 0 或负数时被纠正到 1。
    assert_eq!(list("?limit=0").await, 1);
    assert_eq!(list("?limit=-5").await, 1);
    // offset 正常翻页；260 条数据里跳过 255 条只剩 5 条。
    assert_eq!(list("?limit=10&offset=255").await, 5);
    // 负 offset 按 0 处理，不报错也不越界。
    assert_eq!(list("?limit=3&offset=-10").await, 3);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE username LIKE 'bulk-' || $1::text || '-%'")
        .bind(&suffix)
        .execute(&database)
        .await
        .expect("cleanup bulk users");
    let _ = std::fs::remove_dir_all(key_directory);
}
