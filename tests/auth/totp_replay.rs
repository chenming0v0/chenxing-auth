use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, redis_keyspace::RedisKeyspace, state::AppState};
use redis::AsyncCommands;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{db_isolation, oauth_flow};

const ADMIN_TOKEN: &str = "totp-replay-admin-token";
/// TOTP 步长，与 `auth_factors::totp::TOTP_STEP_SECONDS` 一致。
const STEP_SECONDS: u64 = 30;

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
    let database = db_isolation::isolated_pool("totp_replay", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-replay-{}", Uuid::new_v4()));
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
    config.redis_keyspace = RedisKeyspace::new(&format!("totp-replay-{}", Uuid::new_v4().simple()))
        .expect("test Redis namespace");
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state");
    let router = api::router(state.clone());
    oauth_flow::ensure_owner_bootstrapped(&router, &database, "totp_replay", "totp_replay").await;
    db_isolation::isolate_user_ids(&database, "totp_replay").await;
    (router, state, database, key_directory)
}

async fn json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn request(router: &Router, uri: &str, payload: Value) -> axum::response::Response {
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

async fn request_with_cookie(
    router: &Router,
    uri: &str,
    payload: Value,
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

/// 从合并后的 cookie 头里取出单个 cookie 值。ticket 的 setup 键由 ticket_id 派生，
/// 因此需要拿到 cookie 里的原始 ticket_id 才能定位 Redis 中的待确认注册。
fn cookie_value(cookie: &str, name: &str) -> String {
    cookie
        .split("; ")
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
        .expect("cookie present")
        .to_owned()
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
}

async fn redis_connection() -> redis::aio::MultiplexedConnection {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(redis_url)
        .expect("Redis client")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection")
}

async fn user_id(database: &chenxing_auth::sqlx::PgPool, email: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(database)
        .await
        .expect("user lookup")
}

async fn factor_count(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM user_totp_factors WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("factor count")
}

/// 走完密码登录，返回 pending cookie 头。
async fn password_login(router: &Router, identifier: &str, password: &str) -> String {
    let response = request(
        router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": identifier, "password": password}),
    )
    .await;
    let cookie = pending_cookie(&response);
    let _pending = json(response).await;
    cookie
}

async fn request_with_session(
    router: &Router,
    uri: &str,
    payload: Value,
    cookie: &str,
    csrf: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .body(Body::from(payload.to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("JSON response")
}

fn csrf(cookie: &str) -> String {
    cookie_value(cookie, "chenxing_csrf")
}

/// 在认证会话上启动 TOTP 注册，返回 registration ID 与验证器侧的生成器。
async fn start_enrollment(router: &Router, cookie: &str, csrf: &str) -> (String, TOTP) {
    let response = request_with_session(
        router,
        "/api/v1/auth/security/totp/enrollment/start",
        serde_json::json!({}),
        cookie,
        csrf,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "TOTP enrollment start");
    let setup = json(response).await;
    (
        setup["enrollment_id"]
            .as_str()
            .expect("enrollment ID")
            .to_owned(),
        TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP"),
    )
}

#[tokio::test]
async fn a_totp_time_step_is_single_use_across_tickets_and_inline_login() {
    let (router, _state, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("replay-{suffix}");
    let email = format!("replay-{suffix}@example.com");
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

    let setup_cookie = password_login(&router, &username, password).await;
    let csrf = csrf(&setup_cookie);
    let (enrollment_id, totp) = start_enrollment(&router, &setup_cookie, &csrf).await;
    // 本用例断言的是**登录侧**的跨 ticket 语义，所以注册必须让开当前时间步：
    // 注册确认现在也会 claim `user/timestep`（#301），用当前步注册会让下面第一次
    // 登录被自己的注册挡住。取上一步的码，它仍在 ±1 步的接受窗口内。
    //
    // 「注册用过的码不能被新 ticket 重放」是另一条独立的性质，由
    // `an_enrollment_code_cannot_be_replayed_on_a_fresh_login_ticket` 覆盖。
    let now = now_seconds();
    assert_eq!(
        request_with_session(
            &router,
            "/api/v1/auth/security/totp/enrollment/confirm",
            serde_json::json!({
                "enrollment_id": enrollment_id,
                "code": totp.generate(now.saturating_sub(STEP_SECONDS))
            }),
            &setup_cookie,
            &csrf,
        )
        .await
        .status(),
        StatusCode::OK,
        "enrollment must succeed with a fresh code"
    );

    let first_cookie = password_login(&router, &email, password).await;
    let second_cookie = password_login(&router, &email, password).await;
    let code = totp.generate(now);

    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/login",
            serde_json::json!({"code": code}),
            &first_cookie,
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/login",
            serde_json::json!({"code": code}),
            &second_cookie,
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({
                "identifier": email,
                "password": password,
                "totp_code": code
            }),
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// #301：注册确认用掉的验证码不能再被新的 login ticket 使用。
///
/// 修复前只有登录路径 claim 时间步，注册确认不 claim。因此拿着密码和一个仍在
/// 窗口内的验证码，可以先用它完成注册（消费掉那张 ticket），再取一张新的 login
/// ticket 把同一个码用第二次——一次性验证码的边界只覆盖了登录。
///
/// 这个测试走完整的 HTTP 流程，因为要断言的正是「换一张新 ticket」这个动作：
/// service 层单独调用看不出 ticket 已经换了一张。
#[tokio::test]
async fn an_enrollment_code_cannot_be_replayed_on_a_fresh_login_ticket() {
    let (router, _state, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("enroll-replay-{suffix}");
    let email = format!("enroll-replay-{suffix}@example.com");
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

    let setup_cookie = password_login(&router, &username, password).await;
    let csrf = csrf(&setup_cookie);
    let (enrollment_id, totp) = start_enrollment(&router, &setup_cookie, &csrf).await;
    // 注册与后续两次重放尝试用的是**同一个时间步的同一个码**，这正是攻击场景。
    let now = now_seconds();
    let code = totp.generate(now);
    assert_eq!(
        request_with_session(
            &router,
            "/api/v1/auth/security/totp/enrollment/confirm",
            serde_json::json!({
                "enrollment_id": enrollment_id,
                "code": code
            }),
            &setup_cookie,
            &csrf,
        )
        .await
        .status(),
        StatusCode::OK,
        "enrollment must succeed with a fresh code"
    );
    let user = user_id(&database, &email).await;
    assert_eq!(
        factor_count(&database, user).await,
        1,
        "enrollment must have persisted exactly one factor"
    );

    // 换一张全新的 login ticket，用刚刚注册用过的那个码登录：必须被时间步 claim 挡住。
    let replay_cookie = password_login(&router, &email, password).await;
    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/login",
            serde_json::json!({"code": code}),
            &replay_cookie,
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED,
        "a code already consumed by enrollment must not authenticate a new login ticket"
    );

    // 内联登录走的是 verify_totp（按 user_id 而非 ticket），同一个边界必须同样生效。
    assert_eq!(
        request(
            &router,
            "/api/v1/auth/login",
            serde_json::json!({
                "identifier": email,
                "password": password,
                "totp_code": code
            }),
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED,
        "inline login must not accept the code consumed by enrollment"
    );

    // 下一个时间步的码仍然可用：claim 的粒度是 user/timestep，不是「封禁账号」。
    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/login",
            serde_json::json!({"code": totp.generate(now + STEP_SECONDS)}),
            &replay_cookie,
        )
        .await
        .status(),
        StatusCode::OK,
        "the next timestep must still authenticate; the claim is per-timestep"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(&email)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 待确认认证会话注册的绑定用户不一致时必须 fail closed。
///
/// session enrollment 的 Redis 键由用户与 factor method 派生；测试改写绑定中的
/// user ID，钉住确认时 session、epoch、方法和 enrollment ID 的完整绑定校验。
#[tokio::test]
async fn a_pending_enrollment_bound_to_another_user_is_rejected() {
    let (router, state, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let victim_name = format!("mismatch-victim-{suffix}");
    let victim_email = format!("mismatch-victim-{suffix}@example.com");
    let other_name = format!("mismatch-other-{suffix}");
    let other_email = format!("mismatch-other-{suffix}@example.com");
    let password = "correct horse battery";
    create_user(&router, &victim_name, &victim_email, password).await;
    create_user(&router, &other_name, &other_email, password).await;
    let victim = user_id(&database, &victim_email).await;
    let other = user_id(&database, &other_email).await;

    let cookie = password_login(&router, &victim_name, password).await;
    let csrf = csrf(&cookie);
    let (enrollment_id, totp) = start_enrollment(&router, &cookie, &csrf).await;

    let setup_key = state
        .config
        .redis_keyspace
        .key(&format!("chenxing:auth:session-enrollment:{victim}:totp"));
    let mut connection = redis_connection().await;
    let mut pending: Value = serde_json::from_str(
        &connection
            .get::<_, String>(&setup_key)
            .await
            .expect("pending enrollment payload"),
    )
    .expect("pending enrollment JSON");
    let victim_id = victim.to_string();
    assert_eq!(
        pending["binding"]["user_id"].as_str(),
        Some(victim_id.as_str()),
        "the pending payload must start out bound to the session user"
    );
    pending["binding"]["user_id"] = Value::from(other.to_string());
    let _: () = connection
        .set_ex(
            &setup_key,
            pending.to_string(),
            chenxing_auth::auth_factors::domain::LoginTicket::TTL.whole_seconds() as u64,
        )
        .await
        .expect("poison pending enrollment");

    assert_eq!(
        request_with_session(
            &router,
            "/api/v1/auth/security/totp/enrollment/confirm",
            serde_json::json!({
                "enrollment_id": enrollment_id,
                "code": totp.generate_current().expect("TOTP code")
            }),
            &cookie,
            &csrf,
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST,
        "a pending enrollment bound to another user must fail closed"
    );
    assert_eq!(
        factor_count(&database, victim).await,
        0,
        "the session user must not receive a factor from a mismatched pending payload"
    );
    assert_eq!(
        factor_count(&database, other).await,
        0,
        "the mismatched payload user must not receive a factor either"
    );
    let residual: Option<String> = connection.get(&setup_key).await.expect("residual lookup");
    assert!(
        residual.is_some(),
        "an invalid confirmation must not consume a pending enrollment it does not own"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(vec![victim, other])
        .execute(&database)
        .await
        .expect("cleanup users");
    let _: () = connection
        .del(&setup_key)
        .await
        .expect("cleanup enrollment");
    let _ = std::fs::remove_dir_all(key_directory);
}
