use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{
    api,
    config::Config,
    db,
    sessions::{cookies, domain::Session, store::SessionStore},
    state::AppState,
    users::{domain::ValidatedRegistration, repository as user_repository},
};
use tower::ServiceExt;
use uuid::Uuid;

async fn test_router() -> Router {
    api::router(AppState::for_test().await)
}

#[tokio::test]
async fn session_revoke_requires_a_valid_session_header() {
    let response = test_router()
        .await
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/auth/session")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_revoke_audit_uses_internal_id_without_storing_the_cookie_token() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = PgPoolOptions::new()
        .max_connections(3)
        .connect(&database_url)
        .await
        .expect("PostgreSQL");
    db::migrate(&database).await.expect("migrations");

    let suffix = Uuid::new_v4().simple().to_string();
    let user = user_repository::insert_user(
        &database,
        ValidatedRegistration {
            username: format!("session-audit-{suffix}"),
            email: format!("session-audit-{suffix}@example.com"),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "test-password-hash".to_owned(),
    )
    .await
    .expect("insert audit test user");

    let redis = redis::Client::open(redis_url.as_str()).expect("Redis");
    let sessions = SessionStore::with_metadata_and_key(redis, database.clone(), [0; 32]);
    let mut session =
        Session::new(user.id.to_string(), std::time::Duration::from_secs(60)).expect("session");
    sessions
        .save(&mut session, std::time::Duration::from_secs(60))
        .await
        .expect("save session");

    let key_directory = std::env::temp_dir().join(format!("chenxing-session-audit-{suffix}"));
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
    let router = api::router(AppState::new(config).await.expect("state"));
    let cookie = format!(
        "{}={}; {}={}",
        cookies::SESSION_COOKIE,
        session.token,
        cookies::CSRF_COOKIE,
        session.csrf_token
    );

    let response = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/auth/session")
                .header("cookie", cookie)
                .header("x-csrf-token", &session.csrf_token)
                .body(Body::empty())
                .expect("revoke request"),
        )
        .await
        .expect("revoke response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let expected_resource_id = session.id.to_string();
    let audit: Option<(Option<i64>, Option<String>)> = chenxing_auth::sqlx::query_as(
        "SELECT actor_user_id, resource_id FROM audit_events
         WHERE action = 'session_revoke' AND resource_id = $1",
    )
    .bind(&expected_resource_id)
    .fetch_optional(&database)
    .await
    .expect("query session audit");
    assert_eq!(audit, Some((Some(user.id), Some(expected_resource_id))));

    let leaked_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events
         WHERE action = 'session_revoke' AND resource_id = $1",
    )
    .bind(&session.token)
    .fetch_one(&database)
    .await
    .expect("query leaked session token");
    assert_eq!(
        leaked_count, 0,
        "session token must never be stored in audit"
    );

    chenxing_auth::sqlx::query(
        "DELETE FROM audit_events WHERE action = 'session_revoke' AND resource_id = $1",
    )
    .bind(session.id.to_string())
    .execute(&database)
    .await
    .expect("cleanup audit event");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&database)
        .await
        .expect("cleanup audit test user");
    let _ = std::fs::remove_dir_all(key_directory);
}
