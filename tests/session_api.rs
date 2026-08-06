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

struct RevokeFixture {
    router: Router,
    database: chenxing_auth::sqlx::PgPool,
    user_id: i64,
    session: Session,
    key_directory: std::path::PathBuf,
}

/// 建立一个持久化用户和一个已保存的活跃 Session，用于会话撤销端点的集成测试。
async fn revoke_fixture(label: &str) -> RevokeFixture {
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
            username: format!("{label}-{suffix}"),
            email: format!("{label}-{suffix}@example.com"),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "test-password-hash".to_owned(),
    )
    .await
    .expect("insert session test user");

    let redis = redis::Client::open(redis_url.as_str()).expect("Redis");
    let sessions = SessionStore::with_metadata_and_key(redis, database.clone(), [0; 32]);
    let mut session =
        Session::new(user.id.to_string(), std::time::Duration::from_secs(60)).expect("session");
    sessions
        .save(&mut session, std::time::Duration::from_secs(60))
        .await
        .expect("save session");

    let key_directory = std::env::temp_dir().join(format!("chenxing-{label}-{suffix}"));
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

    RevokeFixture {
        router: api::router(AppState::new(config).await.expect("state")),
        database,
        user_id: user.id,
        session,
        key_directory,
    }
}

fn session_cookie(session: &Session) -> String {
    format!(
        "{}={}; {}={}",
        cookies::SESSION_COOKIE,
        session.token,
        cookies::CSRF_COOKIE,
        session.csrf_token
    )
}

async fn revoke_request(fixture: &RevokeFixture, request: Request<Body>) -> StatusCode {
    fixture
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("revoke response")
        .status()
}

/// 会话仍然可用于认证请求，说明撤销确实没有发生。
async fn session_still_active(fixture: &RevokeFixture) -> bool {
    let status = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("cookie", session_cookie(&fixture.session))
                .body(Body::empty())
                .expect("profile request"),
        )
        .await
        .expect("profile response")
        .status();
    status == StatusCode::OK
}

async fn cleanup(fixture: &RevokeFixture) {
    chenxing_auth::sqlx::query(
        "DELETE FROM audit_events WHERE action = 'session_revoke' AND resource_id = $1",
    )
    .bind(fixture.session.id.to_string())
    .execute(&fixture.database)
    .await
    .expect("cleanup audit event");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(fixture.user_id)
        .execute(&fixture.database)
        .await
        .expect("cleanup session test user");
    let _ = std::fs::remove_dir_all(&fixture.key_directory);
}

#[tokio::test]
async fn session_revoke_requires_valid_session_cookie() {
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
async fn session_revoke_rejects_session_header_without_cookie() {
    // 即使提供 x-chenxing-session 请求头，只要缺失 Session Cookie，必须拒绝。
    let response = test_router()
        .await
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/auth/session")
                .header("x-chenxing-session", "fake-session-token")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("response from router");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// #123 的安全回归测试：撤销端点的 CSRF 三者绑定校验必须无条件执行。
/// 旧实现把校验包在 `if headers.get("cookie").is_some()` 里，并且会话令牌
/// 优先读取 `x-chenxing-session` 请求头，因此不带 Cookie 头的请求可以持有
/// 有效会话令牌直接完成撤销。
#[tokio::test]
async fn session_revoke_rejects_header_session_and_missing_csrf() {
    let fixture = revoke_fixture("session-bypass").await;

    // 1. 持有有效会话令牌但只放在请求头、不发 Cookie：必须拒绝且不得撤销。
    let status = revoke_request(
        &fixture,
        Request::builder()
            .method("DELETE")
            .uri("/api/v1/auth/session")
            .header("x-chenxing-session", &fixture.session.token)
            .body(Body::empty())
            .expect("header session revoke request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        session_still_active(&fixture).await,
        "session header must never revoke a session"
    );

    // 2. Session Cookie 与 CSRF Cookie 齐备但缺少 X-CSRF-Token 请求头：必须拒绝。
    let status = revoke_request(
        &fixture,
        Request::builder()
            .method("DELETE")
            .uri("/api/v1/auth/session")
            .header("cookie", session_cookie(&fixture.session))
            .body(Body::empty())
            .expect("missing CSRF revoke request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        session_still_active(&fixture).await,
        "missing CSRF token must never revoke a session"
    );

    // 3. X-CSRF-Token 与 CSRF Cookie 不一致：必须拒绝。
    let status = revoke_request(
        &fixture,
        Request::builder()
            .method("DELETE")
            .uri("/api/v1/auth/session")
            .header("cookie", session_cookie(&fixture.session))
            .header("x-csrf-token", "mismatched-csrf-token")
            .body(Body::empty())
            .expect("mismatched CSRF revoke request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        session_still_active(&fixture).await,
        "mismatched CSRF token must never revoke a session"
    );

    // 4. 三者绑定齐备的浏览器请求仍然可以正常撤销。
    let status = revoke_request(
        &fixture,
        Request::builder()
            .method("DELETE")
            .uri("/api/v1/auth/session")
            .header("cookie", session_cookie(&fixture.session))
            .header("x-csrf-token", &fixture.session.csrf_token)
            .body(Body::empty())
            .expect("valid revoke request"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        !session_still_active(&fixture).await,
        "a bound browser request must revoke the session"
    );

    cleanup(&fixture).await;
}

#[tokio::test]
async fn session_revoke_audit_uses_internal_id_without_storing_the_cookie_token() {
    let fixture = revoke_fixture("session-audit").await;

    let status = revoke_request(
        &fixture,
        Request::builder()
            .method("DELETE")
            .uri("/api/v1/auth/session")
            .header("cookie", session_cookie(&fixture.session))
            .header("x-csrf-token", &fixture.session.csrf_token)
            .body(Body::empty())
            .expect("revoke request"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let expected_resource_id = fixture.session.id.to_string();
    let audit: Option<(Option<i64>, Option<String>)> = chenxing_auth::sqlx::query_as(
        "SELECT actor_user_id, resource_id FROM audit_events
         WHERE action = 'session_revoke' AND resource_id = $1",
    )
    .bind(&expected_resource_id)
    .fetch_optional(&fixture.database)
    .await
    .expect("query session audit");
    assert_eq!(
        audit,
        Some((Some(fixture.user_id), Some(expected_resource_id)))
    );

    let leaked_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events
         WHERE action = 'session_revoke' AND resource_id = $1",
    )
    .bind(&fixture.session.token)
    .fetch_one(&fixture.database)
    .await
    .expect("query leaked session token");
    assert_eq!(
        leaked_count, 0,
        "session token must never be stored in audit"
    );

    cleanup(&fixture).await;
}
