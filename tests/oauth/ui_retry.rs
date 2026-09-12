use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::SET_COOKIE},
};
use chenxing_auth::sessions::domain::Session;
use redis::AsyncCommands;
use time::OffsetDateTime;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

use crate::harness::HarnessBuilder;
use crate::http;

// 迁移不再种子默认套餐：自助创建 Client 的用例必须自己给用户挂套餐。
use crate::plan_fixtures;

async fn setup() -> (
    Router,
    chenxing_auth::state::AppState,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let harness = HarnessBuilder::new("oauth_ui_retry")
        .admin_token("oauth-ui-retry-admin-token")
        .bootstrap_owner()
        .build()
        .await;
    (
        harness.router,
        harness.state,
        harness.database,
        harness.key_directory,
    )
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
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        http::json_body(response).await["code"],
        "registration_disabled"
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
    let user_id = http::json_body(response).await["id"]
        .as_i64()
        .expect("user id");
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
    let client_id = http::json_body(response).await["client_id"]
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
    let request_id = request_id(&http::location(&response));
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
