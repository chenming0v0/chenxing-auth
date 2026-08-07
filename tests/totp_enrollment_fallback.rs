//! #116 回归测试：登录端点的注册回落语义与限流额度消耗。
//!
//! 这两个测试覆盖 `login_totp` 里 `NoPendingEnrollment` 的判断分支：
//! 已注册 TOTP 的账号没有待确认注册，请求必须回落到 `verify_totp_login`，
//! 并且一次请求只消耗一轮限流额度。

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, state::AppState};
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

async fn setup() -> (
    Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    String,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("totp_enrollment_fallback", &database_url).await;
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-totp-fallback-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("test configuration");
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let email = format!("totp-fallback-{}@example.com", Uuid::new_v4().simple());
    let router = api::router(
        AppState::new_with_pool(config, database.clone())
            .await
            .expect("test state"),
    );
    oauth_flow::ensure_owner_bootstrapped(&router, "totp_enrollment_fallback").await;
    db_isolation::isolate_user_ids(&database, "totp_enrollment_fallback").await;
    (router, database, key_directory, email)
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body"),
    )
    .expect("JSON response")
}

async fn request(
    router: &Router,
    uri: &str,
    payload: serde_json::Value,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

fn pending_cookie(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().expect("cookie pair"))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn request_with_cookie(
    router: &Router,
    uri: &str,
    payload: serde_json::Value,
    cookie: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

/// 注册账号并完成 TOTP 首次注册，返回 TOTP 生成器。
/// 返回时账号已有注册好的 TOTP 因子，后续 login ticket 上不再有待确认注册。
async fn enroll_totp(router: &Router, username: &str, email: &str, password: &str) -> TOTP {
    assert_eq!(
        request(
            router,
            "/api/v1/users",
            serde_json::json!({"username": username, "email": email, "password": password}),
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    let login_response = request(
        router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    let pending_cookie = pending_cookie(&login_response);
    let _pending = json_body(login_response).await;
    let setup = json_body(
        request_with_cookie(
            router,
            "/api/v1/auth/totp/setup",
            serde_json::json!({}),
            &pending_cookie,
        )
        .await,
    )
    .await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    // 专用的注册确认端点完成注册，登录端点此后只应走验证路径。
    assert_eq!(
        request_with_cookie(
            router,
            "/api/v1/auth/totp/setup/confirm",
            serde_json::json!({
                "code": totp.generate_current().expect("enrollment code")
            }),
            &pending_cookie,
        )
        .await
        .status(),
        StatusCode::OK
    );
    totp
}

/// 取一张新的 login ticket。账号已有因子，因此状态是 `factor_required`。
async fn factor_login_ticket(router: &Router, username: &str, password: &str) -> String {
    let response = request(
        router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    let cookie = pending_cookie(&response);
    let body = json_body(response).await;
    assert_eq!(body["status"], "factor_required");
    assert!(body.get("login_ticket").is_none());
    cookie
}

async fn cleanup(
    database: &chenxing_auth::sqlx::PgPool,
    email: &str,
    key_directory: std::path::PathBuf,
) {
    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
// #116：没有待确认注册时，登录端点必须回落到已注册因子的验证路径
async fn totp_login_falls_back_to_verification_without_pending_enrollment() {
    let (router, database, key_directory, email) = setup().await;
    let username = format!("totp-fallback-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    let totp = enroll_totp(&router, &username, &email, password).await;

    let ticket = factor_login_ticket(&router, &username, password).await;

    // 这张 ticket 上没有待确认注册，`confirm_totp_enrollment` 返回
    // `NoPendingEnrollment`，handler 回落到 `verify_totp_login`：错误码仍是因子失败。
    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/login",
            serde_json::json!({"code": "000000"}),
            &ticket,
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    // 正确验证码走回落路径完成登录并签发会话。
    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": totp.generate_current().expect("login code")}),
        &ticket,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("set-cookie").is_some(),
        "fallback verification must issue a session cookie"
    );

    cleanup(&database, &email, key_directory).await;
}

#[tokio::test]
// #116：回落路径每次请求只消耗一轮 ticket 维度额度
//
// 修复前的代码在 NoPendingEnrollment 情况下不存在双重预留问题（因为不预留就返回了），
// 但这个测试仍然作为回归守卫：确认回落路径与注册路径一样正确执行单轮预留语义，
// ticket 限流阈值是完整的 5 次而不是其他值。
async fn totp_login_fallback_consumes_one_quota_round_per_request() {
    let (router, database, key_directory, email) = setup().await;
    let username = format!("totp-quota-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    let totp = enroll_totp(&router, &username, &email, password).await;

    let ticket = factor_login_ticket(&router, &username, password).await;

    let ticket_limit = chenxing_auth::auth_limiter::FailureDimension::Ticket.limit();
    for attempt in 1..ticket_limit {
        assert_eq!(
            request_with_cookie(
                &router,
                "/api/v1/auth/totp/login",
                serde_json::json!({"code": "000000"}),
                &ticket,
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} below the ticket limit must stay an authentication failure"
        );
    }

    // 阈值内的失败次数不应烧掉 ticket：正确验证码仍然可以完成登录。
    let response = request_with_cookie(
        &router,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": totp.generate_current().expect("login code")}),
        &ticket,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "ticket must survive {} failures when each request reserves one round",
        ticket_limit - 1
    );

    cleanup(&database, &email, key_directory).await;
}
