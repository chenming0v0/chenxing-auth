use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{
    api,
    config::Config,
    db,
    sessions::{cookies, domain::Session, store::SessionStore},
    state::AppState,
};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup() -> (
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
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
    chenxing_auth::sqlx::query("TRUNCATE users RESTART IDENTITY CASCADE")
        .execute(&database)
        .await
        .expect("reset identity test database");
    let redis = redis::Client::open(redis_url.as_str()).expect("Redis");
    let mut redis_connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut redis_connection)
        .await
        .expect("reset Redis test database");
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
        api::router(AppState::new(config).expect("state")),
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

async fn browser_session(database_url: &str, redis_url: &str, user_id: i64) -> (String, String) {
    let database = PgPoolOptions::new()
        .max_connections(2)
        .connect(database_url)
        .await
        .expect("session PostgreSQL");
    let redis = redis::Client::open(redis_url).expect("session Redis");
    let store = SessionStore::with_metadata(redis, database);
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
    assert_eq!(response.status(), StatusCode::CREATED);
    let user = json(response).await;
    let user_id = user["user"]["id"].as_i64().expect("numeric user id");
    assert_eq!(user_id, 3);
    assert_eq!(user["user"]["role"], "user");

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
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
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

    let (managed_cookie, managed_csrf) =
        browser_session(&database_url, &redis_url, managed_id).await;
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
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (owner_cookie, owner_csrf) = browser_session(&database_url, &redis_url, 1).await;
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
