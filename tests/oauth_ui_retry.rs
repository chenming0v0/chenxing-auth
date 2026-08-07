use axum::{
    Router,
    body::Body,
    http::{
        Request, StatusCode,
        header::{LOCATION, SET_COOKIE},
    },
};
use chenxing_auth::{api, config::Config, sessions::domain::Session, state::AppState};
use redis::AsyncCommands;
use serde_json::Value;
use time::OffsetDateTime;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

// 迁移不再种子默认套餐：自助创建 Client 的用例必须自己给用户挂套餐。
#[path = "support/plan_fixtures.rs"]
mod plan_fixtures;

async fn setup() -> (
    Router,
    AppState,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("oauth_ui_retry", &database_url).await;
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-oauth-ui-retry-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "oauth-ui-retry-admin-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("state");
    let router = api::router(state.clone());
    oauth_flow::ensure_owner_bootstrapped(&router, "oauth_ui_retry").await;
    (router, state, database, key_directory)
}

async fn json(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("JSON")
}

fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("location")
        .to_owned()
}

fn request_id(location: &str) -> String {
    Url::parse(&format!("http://localhost{location}"))
        .expect("request URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request id")
}

/// Set-Cookie 头中提取 `name=value` 对，用于构造 Cookie 请求头。
fn set_cookie_pair(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .find_map(|value| {
            let s = value.to_str().ok()?;
            let pair = s.split(';').next()?;
            pair.trim()
                .starts_with(&format!("{name}="))
                .then(|| pair.trim().to_owned())
        })
}

fn session_cookie(session: &Session) -> String {
    format!(
        "chenxing_session={}; chenxing_csrf={}",
        session.token, session.csrf_token
    )
}

#[tokio::test]
async fn oauth_ui_approval_failure_keeps_pending_request_for_retry() {
    let (router, state, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("oauth-ui-retry-{suffix}@example.com");
    let username = format!("oauth-ui-retry-{suffix}");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": "correct horse battery"
                    })
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

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer oauth-ui-retry-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": "correct horse battery"
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user_id = json(response).await["id"].as_i64().expect("user id");
    // 自助创建 Client 需要生效套餐；迁移不再种子默认套餐，这里显式挂一个。
    plan_fixtures::assign_private_plan(
        &database,
        user_id,
        plan_fixtures::PlanLimits::legacy_default(),
    )
    .await;
    let mut session =
        Session::new(user_id.to_string(), std::time::Duration::from_secs(3600)).expect("session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    let cookie = session_cookie(&session);
    let csrf = session.csrf_token.clone();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "OAuth UI Retry Client",
                        "redirect_uris": ["https://oauth-ui-retry.example/callback"],
                        "scopes": ["openid", "profile"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let client_id = json(response).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned();
    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Foauth-ui-retry.example%2Fcallback&response_type=code&scope=openid%20profile&state=oauth-ui-retry-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("accept", "text/html")
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    let request_id = request_id(&location(&response));
    // 授权持有者 Cookie 下发于 authorize 响应，必须随 bind 请求一起送回（#115）。
    let authz_holder_pair = set_cookie_pair(&response, "chenxing_authz_holder")
        .expect("authz holder cookie must be present in authorize response");
    let bind_cookie = format!("{cookie}; {authz_holder_pair}");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/oauth/authorize/requests/{request_id}/bind"
                ))
                .header("cookie", &bind_cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .expect("bind request"),
        )
        .await
        .expect("bind response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let date = OffsetDateTime::now_utc().date();
    let day_key = format!("chenxing:oauth:quota:{client_id}:day:{date}");
    let month_key = format!(
        "chenxing:oauth:quota:{client_id}:month:{:04}-{:02}",
        date.year(),
        date.month() as u8
    );
    let mut redis_connection = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: () = redis_connection
        .set(&day_key, 2_500_i64)
        .await
        .expect("set daily quota");
    let _: () = redis_connection
        .set(&month_key, 50_000_i64)
        .await
        .expect("set monthly quota");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("quota failure approval request"),
        )
        .await
        .expect("quota failure approval response");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("retry inspect request"),
        )
        .await
        .expect("retry inspect response");
    assert_eq!(response.status(), StatusCode::OK);

    let _: usize = redis_connection
        .del(&day_key)
        .await
        .expect("clear daily quota");
    let _: usize = redis_connection
        .del(&month_key)
        .await
        .expect("clear monthly quota");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("retry approval request"),
        )
        .await
        .expect("retry approval response");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("consumed inspect request"),
        )
        .await
        .expect("consumed inspect response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
