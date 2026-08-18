use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{LOCATION, SET_COOKIE, WWW_AUTHENTICATE},
    },
};
use chenxing_auth::{api, config::Config, state::AppState};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("browser_flow", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-browser-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.admin_token = "browser-admin-token".to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (
        api::router(
            AppState::new_with_pool(config, database.clone())
                .await
                .expect("test state"),
        ),
        database,
        key_directory,
    )
}

async fn body(response: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body")
            .to_vec(),
    )
    .expect("UTF-8 response")
}

/// Joins the first pair of every Set-Cookie header into a Cookie request value.
fn cookies(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie header")
                .split(';')
                .next()
                .expect("cookie pair")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location")
        .to_owned()
}

fn cookie_value(cookie_header: &str, name: &str) -> String {
    cookie_header
        .split(';')
        .find_map(|part| part.trim().strip_prefix(&format!("{name}=")))
        .expect("cookie present")
        .to_owned()
}

fn request_id_from(location: &str) -> String {
    Url::parse(&format!("http://localhost{location}"))
        .expect("redirect URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request id")
}

/// Full browser OAuth flow entirely over JSON, mirroring how the React SPA drives it:
/// authorize (creates pending, redirects to SPA login) → JSON password login
/// (issues session) → bind session to the pending request → inspect → approve →
/// authorization code. Re-running authorize with a stored consent yields a code directly.
#[tokio::test]
async fn spa_json_oauth_flow_requires_session_and_reuses_consent() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("browser-owner-{suffix}"),
                        "email": format!("browser-owner-{suffix}@example.com"),
                        "password": "correct horse battery"
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert!(matches!(
        response.status(),
        StatusCode::CREATED | StatusCode::CONFLICT
    ));
    // bootstrap 会把 users 序列重置回 1，必须重新施加用户 ID 偏移，否则注册
    // 用户拿到小号 ID，TOTP 时间步 claim 键在共享 Redis 上跨测试碰撞（#301）。
    db_isolation::isolate_user_ids(&database, "browser_flow").await;

    let email = format!("browser-{suffix}@example.com");
    let username = format!("browser-{suffix}");
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
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let registration_error: serde_json::Value =
        serde_json::from_str(&body(response).await).expect("registration error JSON");
    assert_eq!(registration_error["code"], "registration_disabled");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer browser-admin-token")
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

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer browser-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "Browser Client",
                        "redirect_uris": ["https://browser.example/callback"],
                        "scopes": ["openid", "profile"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    let client: serde_json::Value =
        serde_json::from_str(&body(response).await).expect("client JSON");
    let client_id = client["client_id"].as_str().expect("client id").to_owned();

    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fbrowser.example%2Fcallback&response_type=code&scope=openid%20profile&state=browser-state&nonce=browser-nonce&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
    );

    // A valid client still requires a session for non-browser OAuth requests.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .body(Body::empty())
                .expect("API authorize request"),
        )
        .await
        .expect("API authorize response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Session realm=\"oauth\"")
    );
    let error: serde_json::Value =
        serde_json::from_str(&body(response).await).expect("OAuth authorization error JSON");
    assert_eq!(error["error"], "login_required");
    assert_eq!(
        error["error_description"],
        "an authenticated session is required"
    );

    // Unauthenticated browser hit: pending is created, user is sent to the SPA login page.
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
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let login_location = location(&response);
    assert!(
        login_location.starts_with("/login?request_id="),
        "expected SPA login redirect, got {login_location}"
    );
    let request_id = request_id_from(&login_location);
    // 授权持有者 Cookie 下发于 authorize 响应，必须随 bind 请求一起送回（#115）。
    let authz_holder_cookie = cookies(&response);
    assert!(
        authz_holder_cookie.starts_with("chenxing_authz_holder="),
        "authorize must issue the authorization holder cookie, got {authz_holder_cookie}"
    );

    // SPA logs in over JSON. Password-only accounts receive a normal session.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"identifier": username, "password": password}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    assert_eq!(response.status(), StatusCode::OK);
    let session_cookies = cookies(&response);
    let login_body: serde_json::Value =
        serde_json::from_str(&body(response).await).expect("login JSON");
    assert!(login_body["expires_at"].as_str().is_some());
    let csrf = cookie_value(&session_cookies, "chenxing_csrf");

    // 回归（#115）：无持有者 Cookie 的绑定请求必须被拒绝（403）。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/oauth/authorize/requests/{request_id}/bind"
                ))
                .header("cookie", &session_cookies)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .expect("bind without holder request"),
        )
        .await
        .expect("bind without holder response");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "bind without holder cookie must return 403"
    );

    // 回归（#115）：伪造的持有者 Cookie 同样被拒绝（403）。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/oauth/authorize/requests/{request_id}/bind"
                ))
                .header(
                    "cookie",
                    format!("{session_cookies}; chenxing_authz_holder=wrong_holder_value"),
                )
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .expect("bind with wrong holder request"),
        )
        .await
        .expect("bind with wrong holder response");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "bind with wrong holder cookie must return 403"
    );

    // Bind the freshly-issued session to the pending authorization request.
    // 合并持有者 Cookie（来自 authorize）与会话 Cookie（来自 TOTP 登录）。
    let all_cookies = format!("{session_cookies}; {authz_holder_cookie}");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/oauth/authorize/requests/{request_id}/bind"
                ))
                .header("cookie", &all_cookies)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .expect("bind request"),
        )
        .await
        .expect("bind response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 幂等重试：同一会话 + 同一持有者 Cookie 重复绑定仍返回 204。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/oauth/authorize/requests/{request_id}/bind"
                ))
                .header("cookie", &all_cookies)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .expect("idempotent bind request"),
        )
        .await
        .expect("idempotent bind response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Inspect returns safe consent data for the bound request.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &session_cookies)
                .body(Body::empty())
                .expect("inspect request"),
        )
        .await
        .expect("inspect response");
    assert_eq!(response.status(), StatusCode::OK);
    let pending: serde_json::Value =
        serde_json::from_str(&body(response).await).expect("pending JSON");
    assert_eq!(pending["client_name"], "Browser Client");
    assert_eq!(pending["redirect_host"], "browser.example");

    // Approve → authorization code redirect to the client callback.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &session_cookies)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"decision": "approve"}).to_string(),
                ))
                .expect("decide request"),
        )
        .await
        .expect("decide response");
    assert_eq!(response.status(), StatusCode::OK);
    let decision: serde_json::Value =
        serde_json::from_str(&body(response).await).expect("decision JSON");
    assert_eq!(decision["decision"], "approve");
    let first_code = Url::parse(decision["redirect_to"].as_str().expect("redirect_to"))
        .expect("callback URL")
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .expect("authorization code");
    assert!(!first_code.is_empty());

    // Re-running authorize with a stored consent + session cookie issues a code directly.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("accept", "text/html")
                .header("cookie", &session_cookies)
                .body(Body::empty())
                .expect("repeat authorize request"),
        )
        .await
        .expect("repeat authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let repeat_location = location(&response);
    assert!(
        repeat_location.contains("code="),
        "expected direct code redirect, got {repeat_location}"
    );

    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    chenxing_auth::sqlx::query("DELETE FROM user_consents WHERE user_id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("consent cleanup");
    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(&client_id)
        .execute(&database)
        .await
        .expect("client cleanup");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}
