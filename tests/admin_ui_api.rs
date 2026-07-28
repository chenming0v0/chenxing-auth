use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::SET_COOKIE},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{api, config::Config, db, state::AppState};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
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

fn cookies(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie")
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test]
async fn owner_can_use_admin_ui_queries_but_normal_user_cannot() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("admin-ui-user-{suffix}");
    let email = format!("admin-ui-user-{suffix}@example.com");
    let password = "correct horse battery";
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

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"identifier": email, "password": password}).to_string(),
                ))
                .expect("user login request"),
        )
        .await
        .expect("user login response");
    let user_cookies = cookies(&response);
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
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

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
             (id, actor_type, actor_id, action, resource_type, resource_id, metadata, created_at)
             VALUES ($1, 'test', NULL, $2, 'test', NULL, '{}'::jsonb, NOW())",
        )
        .bind(Uuid::new_v4())
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
