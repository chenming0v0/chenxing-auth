//! #116 回归测试：登录端点的注册回落语义与限流额度消耗；#338 回归测试：
//! TOTP 登录路径的 ticket 有效期判定必须与签发同源（注入时钟）。
//!
//! 前两个测试覆盖 `login_totp` 里 `NoPendingEnrollment` 的判断分支：
//! 已注册 TOTP 的账号没有待确认注册，请求必须回落到 `verify_totp_login`，
//! 并且一次请求只消耗一轮限流额度。第三个测试把注入时钟推到 ticket 过期
//! 之后，断言同一张 Redis 里仍活着的 ticket 被判无效。

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api, auth_factors::domain::LoginTicket, clock::SharedClock, config::Config, state::AppState,
};
use time::{Duration, OffsetDateTime};
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

const ADMIN_TOKEN: &str = "totp-fallback-admin-token";

async fn setup() -> (
    Router,
    chenxing_auth::state::AppState,
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
    config.admin_token = ADMIN_TOKEN.to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let email = format!("totp-fallback-{}@example.com", Uuid::new_v4().simple());
    let fixed_now = fixed_totp_now();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state")
        .with_clock(SharedClock::fixed(fixed_now));
    let router = api::router(state.clone());
    oauth_flow::ensure_owner_bootstrapped(
        &router,
        &database,
        "totp_enrollment_fallback",
        "totp_enrollment_fallback",
    )
    .await;
    db_isolation::isolate_user_ids(&database, "totp_enrollment_fallback").await;
    (router, state, database, key_directory, email)
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

async fn create_user(router: &Router, username: &str, email: &str, password: &str) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "email": email,
                        "password": password,
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
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

fn csrf(cookies: &str) -> &str {
    cookies
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("csrf cookie")
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

async fn request_with_cookie_and_csrf(
    router: &Router,
    uri: &str,
    payload: serde_json::Value,
    cookie: &str,
    csrf_token: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf_token)
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

/// 注册账号并完成 TOTP 首次注册，返回 TOTP 生成器。
/// 返回时账号已有注册好的 TOTP 因子，后续 login ticket 上不再有待确认注册。
async fn enroll_totp(
    router: &Router,
    username: &str,
    email: &str,
    password: &str,
    now: OffsetDateTime,
) -> TOTP {
    create_user(router, username, email, password).await;
    let login_response = request(
        router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    assert_eq!(login_response.status(), StatusCode::OK);
    let cookie = pending_cookie(&login_response);
    let csrf_token = csrf(&cookie).to_owned();
    let _login_body = json_body(login_response).await;
    
    let setup = json_body(
        request_with_cookie_and_csrf(
            router,
            "/api/v1/auth/security/totp/enrollment/start",
            serde_json::json!({}),
            &cookie,
            &csrf_token,
        )
        .await,
    )
    .await;
    let enrollment_id = setup["enrollment_id"]
        .as_str()
        .expect("enrollment ID")
        .to_owned();
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    // 专用的注册确认端点完成注册，登录端点此后只应走验证路径。
    //
    // 注册用**上一个时间步**的码：注册确认现在也会 claim `user/timestep`（#301），
    // 用当前步的码会把当前步烧掉，后面断言「正确验证码能登录」的调用就会被自己的
    // 注册挡住。上一步的码仍在 ±1 步接受窗口内，且不占用后续登录要用的当前步。
    assert_eq!(
        request_with_cookie_and_csrf(
            router,
            "/api/v1/auth/security/totp/enrollment/confirm",
            serde_json::json!({
                "enrollment_id": enrollment_id,
                "code": totp.generate(previous_timestep_timestamp(now))
            }),
            &cookie,
            &csrf_token,
        )
        .await
        .status(),
        StatusCode::OK
    );
    totp
}

/// 固定在当前 TOTP 时间步中点，避免请求跨过 30 秒边界时测试输入自行过期。
fn fixed_totp_now() -> OffsetDateTime {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let midpoint = timestamp - timestamp.rem_euclid(30) + 15;
    OffsetDateTime::from_unix_timestamp(midpoint).expect("current TOTP timestamp")
}

fn totp_timestamp(now: OffsetDateTime) -> u64 {
    u64::try_from(now.unix_timestamp()).expect("non-negative TOTP timestamp")
}

/// 上一个时间步的时间戳，用于生成「不占用当前步」的注册确认码（#301）。
fn previous_timestep_timestamp(now: OffsetDateTime) -> u64 {
    totp_timestamp(now).saturating_sub(30)
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
    let (router, state, database, key_directory, email) = setup().await;
    let username = format!("totp-fallback-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    let now = state.clock.now();
    let totp = enroll_totp(&router, &username, &email, password, now).await;

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
        serde_json::json!({"code": totp.generate(totp_timestamp(now))}),
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
    let (router, state, database, key_directory, email) = setup().await;
    let username = format!("totp-quota-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    let now = state.clock.now();
    let totp = enroll_totp(&router, &username, &email, password, now).await;

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
        serde_json::json!({"code": totp.generate(totp_timestamp(now))}),
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

#[tokio::test]
// #338：TOTP 登录路径判 ticket 有效期必须用注入时钟，与签发同源。
//
// 同一套 DB/Redis 上搭两个 router：基准固定时钟签发 ticket，另一张把固定时钟
// 推到 ticket TTL 之后。Redis 键的 TTL 是真实 300 秒，所以同一张 ticket 同时满足
// 「基准时钟下刚签发」与「未来时钟下已过期」——只有时钟同源的实现能判出后者。
// 修复前 totp_service/totp_enrollment 直接读 `OffsetDateTime::now_utc()`，
// 这张 ticket 会错误地继续走到验证码检查（401），而不是 ticket 无效（400）。
async fn totp_login_ticket_expiry_is_driven_by_the_injected_clock() {
    let (router, state, database, key_directory, email) = setup().await;
    let username = format!("totp-clock-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    let now = state.clock.now();
    let totp = enroll_totp(&router, &username, &email, password, now).await;
    let ticket = factor_login_ticket(&router, &username, password).await;

    // 基准时钟下 ticket 刚签发：错误验证码得到的是因子失败（401）而不是
    // ticket 无效（400），证明这张 ticket 本身有效且 Redis 里还活着。
    let active = request_with_cookie(
        &router,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": "000000"}),
        &ticket,
    )
    .await;
    assert_eq!(active.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(active).await["code"], "invalid_factor");

    // 同一张 ticket，把注入时钟推到 TTL 之后：真实 Redis TTL 还剩约 5 分钟，
    // 基准时钟下依然有效，但未来时钟必须判它过期。
    let future = now + LoginTicket::TTL + Duration::minutes(1);
    let future_router = api::router(state.with_clock(SharedClock::fixed(future)));
    let expired = request_with_cookie(
        &future_router,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": "000000"}),
        &ticket,
    )
    .await;
    assert_eq!(expired.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(expired).await["code"], "invalid_login_ticket");

    // 过期判定不得消耗 ticket：回到基准时钟，同一张 ticket 用正确验证码仍能
    // 完成登录——证明上面的 400 纯粹是时钟判出的过期，不是 ticket 本身失效。
    let recovered = request_with_cookie(
        &router,
        "/api/v1/auth/totp/login",
        serde_json::json!({"code": totp.generate(totp_timestamp(now))}),
        &ticket,
    )
    .await;
    assert_eq!(recovered.status(), StatusCode::OK);

    cleanup(&database, &email, key_directory).await;
}
