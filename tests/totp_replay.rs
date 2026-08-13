use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{api, config::Config, state::AppState};
use redis::AsyncCommands;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

const ADMIN_TOKEN: &str = "totp-replay-admin-token";
/// TOTP 步长，与 `auth_factors::totp::TOTP_STEP_SECONDS` 一致。
const STEP_SECONDS: u64 = 30;
/// 待确认注册在 Redis 中的键前缀，与 `auth_factors::totp_enrollment` 一致。
const TOTP_SETUP_PREFIX: &str = "chenxing:auth:totp-setup:";

async fn setup() -> (Router, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
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
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let router = api::router(
        AppState::new_with_pool(config, database.clone())
            .await
            .expect("test state"),
    );
    oauth_flow::ensure_owner_bootstrapped(&router, &database, "totp_replay", "totp_replay").await;
    db_isolation::isolate_user_ids(&database, "totp_replay").await;
    (router, database, key_directory)
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

/// 在给定的 pending cookie 上启动 TOTP 注册，返回验证器侧的 TOTP 生成器。
async fn start_enrollment(router: &Router, cookie: &str) -> TOTP {
    let response = request_with_cookie(
        router,
        "/api/v1/auth/totp/setup",
        serde_json::json!({}),
        cookie,
    )
    .await;
    let setup = json(response).await;
    TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP")
}

#[tokio::test]
async fn a_totp_time_step_is_single_use_across_tickets_and_inline_login() {
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("replay-{suffix}");
    let email = format!("replay-{suffix}@example.com");
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

    let setup_cookie = password_login(&router, &username, password).await;
    let totp = start_enrollment(&router, &setup_cookie).await;
    // 本用例断言的是**登录侧**的跨 ticket 语义，所以注册必须让开当前时间步：
    // 注册确认现在也会 claim `user/timestep`（#301），用当前步注册会让下面第一次
    // 登录被自己的注册挡住。取上一步的码，它仍在 ±1 步的接受窗口内。
    //
    // 「注册用过的码不能被新 ticket 重放」是另一条独立的性质，由
    // `an_enrollment_code_cannot_be_replayed_on_a_fresh_login_ticket` 覆盖。
    let now = now_seconds();
    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/setup/confirm",
            serde_json::json!({"code": totp.generate(now.saturating_sub(STEP_SECONDS))}),
            &setup_cookie,
        )
        .await
        .status(),
        StatusCode::OK
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
    let (router, database, key_directory) = setup().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("enroll-replay-{suffix}");
    let email = format!("enroll-replay-{suffix}@example.com");
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

    let setup_cookie = password_login(&router, &username, password).await;
    let totp = start_enrollment(&router, &setup_cookie).await;
    // 注册与后续两次重放尝试用的是**同一个时间步的同一个码**，这正是攻击场景。
    let now = now_seconds();
    let code = totp.generate(now);
    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/setup/confirm",
            serde_json::json!({"code": code}),
            &setup_cookie,
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

/// #301：待确认注册的 `user_id` 与 login ticket 不一致时必须 fail closed。
///
/// setup 键当前由 ticket_id 派生，正常流程下两者不可能不一致，所以这里直接改写
/// Redis 里的 pending 载荷来构造这个状态。这不是在测试一条可从外部触发的攻击
/// 路径，而是钉住那条防御性校验：一旦键的派生方式改变，缺了它就会把 A 预留的
/// 种子写成 B 的因子，且 replay claim 会打在错误的用户命名空间上。
///
/// 判别力来自状态码：缺少校验时，服务端会拿着这份（用真实密钥加密的）种子继续
/// 往下走，把因子写给 ticket 上的用户并签发会话，返回 200；有校验时在任何解密、
/// 限流和写库之前就返回 400。
#[tokio::test]
async fn a_pending_enrollment_bound_to_another_user_is_rejected() {
    let (router, database, key_directory) = setup().await;
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
    let ticket_id = cookie_value(&cookie, "chenxing_login_ticket");
    let totp = start_enrollment(&router, &cookie).await;

    // 把预留载荷的 user_id 改成另一个用户，密文保持原样：只有绑定被破坏，
    // 种子仍然是服务端能正常解密的那一份。
    let setup_key = format!("{TOTP_SETUP_PREFIX}{ticket_id}");
    let mut connection = redis_connection().await;
    let mut pending: Value = serde_json::from_str(
        &connection
            .get::<_, String>(&setup_key)
            .await
            .expect("pending enrollment payload"),
    )
    .expect("pending enrollment JSON");
    assert_eq!(
        pending["user_id"].as_i64(),
        Some(victim),
        "the pending payload must start out bound to the ticket user"
    );
    pending["user_id"] = Value::from(other);
    // TTL 用 login ticket 的完整寿命重写，而不是读回剩余 TTL 再套用：
    // 读回值只在这一瞬间正确，而本用例后面还要发两个请求。
    let _: () = connection
        .set_ex(
            &setup_key,
            pending.to_string(),
            chenxing_auth::auth_factors::domain::LoginTicket::TTL.whole_seconds() as u64,
        )
        .await
        .expect("poison pending enrollment");

    // 正确的验证码 + 被破坏的绑定：必须拒绝，且拒绝发生在写库之前。
    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/setup/confirm",
            serde_json::json!({"code": totp.generate_current().expect("TOTP code")}),
            &cookie,
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST,
        "a pending enrollment bound to another user must fail closed"
    );
    assert_eq!(
        factor_count(&database, victim).await,
        0,
        "the ticket user must not receive a factor from a mismatched pending payload"
    );
    assert_eq!(
        factor_count(&database, other).await,
        0,
        "the payload user must not receive a factor either"
    );

    // fail closed 连 ticket 一起废掉：绑定不可信之后，这张 ticket 上的任何后续
    // 判断都失去依据。重放同一张 ticket 只能再拿到 400。
    assert_eq!(
        request_with_cookie(
            &router,
            "/api/v1/auth/totp/setup/confirm",
            serde_json::json!({"code": totp.generate_current().expect("TOTP code")}),
            &cookie,
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST,
        "the ticket must have been invalidated along with the pending enrollment"
    );
    let residual: Option<String> = connection.get(&setup_key).await.expect("residual lookup");
    assert!(
        residual.is_none(),
        "the mismatched pending enrollment must have been deleted"
    );

    let user_ids = vec![victim, other];
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&user_ids)
        .execute(&database)
        .await
        .expect("cleanup users");
    let _ = std::fs::remove_dir_all(key_directory);
}
