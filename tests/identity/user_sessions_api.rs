use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::SET_COOKIE},
};
use chenxing_auth::{api, config::Config, state::AppState};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{db_isolation, oauth_flow};

const ADMIN_TOKEN: &str = "user-sessions-admin-token";

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("user_sessions_api", &database_url).await;
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-session-ui-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = ADMIN_TOKEN.to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let router = api::router(
        AppState::new_with_pool(config, database.clone())
            .await
            .expect("state"),
    );
    oauth_flow::ensure_owner_bootstrapped(
        &router,
        &database,
        "user_sessions_api",
        "user_sessions_api",
    )
    .await;
    db_isolation::isolate_user_ids(&database, "user_sessions_api").await;
    (router, database, key_directory)
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

fn csrf(cookies: &str) -> String {
    cookies
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
        .to_owned()
}

async fn register(router: &Router, username: &str, email: &str, password: &str) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
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
}

async fn login(
    router: &Router,
    _database: &chenxing_auth::sqlx::PgPool,
    identifier: &str,
    _email: &str,
    password: &str,
) -> (String, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"identifier": identifier, "password": password}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    if response.status() == StatusCode::ACCEPTED {
        let pending = json(response).await;
        panic!("unexpected pending login response: {pending}");
    }
    assert_eq!(response.status(), StatusCode::OK);
    let cookie_header = cookies(&response);
    let csrf_token = csrf(&cookie_header);
    (cookie_header, csrf_token)
}

#[tokio::test]
async fn user_can_update_profile_list_sessions_and_rotate_password() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("sessions-{suffix}@example.com");
    let old_password = "correct horse battery";
    let new_password = "new correct password";
    let username = format!("sessions-{suffix}");
    register(&router, &username, &email, old_password).await;
    let (first_cookies, first_csrf) =
        login(&router, &database, &username, &email, old_password).await;
    let (second_cookies, _) = login(&router, &database, &email, &email, old_password).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/auth/me")
                .header("cookie", &first_cookies)
                .header("x-csrf-token", &first_csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"display_name":"Session User"}"#))
                .expect("profile update request"),
        )
        .await
        .expect("profile update response");
    assert_eq!(response.status(), StatusCode::OK);
    let profile = json(response).await;
    assert_eq!(profile["username"], username);
    assert_eq!(profile["display_name"], "Session User");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/sessions")
                .header("cookie", &first_cookies)
                .body(Body::empty())
                .expect("session list request"),
        )
        .await
        .expect("session list response");
    assert_eq!(response.status(), StatusCode::OK);
    let sessions = json(response).await;
    assert!(sessions["items"].as_array().expect("sessions").len() >= 2);
    assert_eq!(
        sessions["items"]
            .as_array()
            .expect("sessions")
            .iter()
            .filter(|session| session["current"] == true)
            .count(),
        1
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/password")
                .header("cookie", &first_cookies)
                .header("x-csrf-token", &first_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "current_password": old_password,
                        "new_password": new_password
                    })
                    .to_string(),
                ))
                .expect("password update request"),
        )
        .await
        .expect("password update response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("cookie", &second_cookies)
                .body(Body::empty())
                .expect("revoked session request"),
        )
        .await
        .expect("revoked session response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "identifier": email,
                        "password": new_password
                    })
                    .to_string(),
                ))
                .expect("new password login request"),
        )
        .await
        .expect("new password login response");
    assert_eq!(response.status(), StatusCode::OK);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
