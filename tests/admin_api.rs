use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
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

#[tokio::test]
async fn bootstrap_admin_can_login_and_use_cookie_session() {
    let (router, database, key_directory) = setup().await;
    let email = format!("admin-{}@example.com", Uuid::new_v4().simple());
    let password = "administrator-password";

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie")
                .split(';')
                .next()
                .expect("pair")
        })
        .collect::<Vec<_>>()
        .join("; ");
    assert!(cookies.contains("chenxing_admin_session="));
    assert!(cookies.contains("chenxing_admin_csrf="));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/audit")
                .header("cookie", &cookies)
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
                        "email": format!("operator-{email}"),
                        "password": password,
                        "role": "operator"
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

    let user_email = format!("managed-{email}");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": user_email, "password": password}).to_string(),
                ))
                .expect("user registration request"),
        )
        .await
        .expect("user registration response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user = json(response).await;
    let user_id = user["user"]["id"].as_str().expect("user id").to_owned();

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
                .header("authorization", "Bearer bootstrap-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": format!("second-{email}"), "password": password})
                        .to_string(),
                ))
                .expect("second bootstrap request"),
        )
        .await
        .expect("second bootstrap response");
    assert_eq!(response.status(), StatusCode::CONFLICT);

    chenxing_auth::sqlx::query("DELETE FROM admins WHERE email = $1")
        .bind(&email)
        .execute(&database)
        .await
        .expect("cleanup admin");
    chenxing_auth::sqlx::query("DELETE FROM admins WHERE email = $1")
        .bind(format!("operator-{email}"))
        .execute(&database)
        .await
        .expect("cleanup operator");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(&user_email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
