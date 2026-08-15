use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    auth_factors::{domain::FactorMethod, service::TotpConfirmation},
    clock::SharedClock,
    config::Config,
    state::AppState,
    users::domain::AuthenticatedUser,
};
use totp_rs::TOTP;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;
#[path = "support/totp_time.rs"]
mod totp_time;

const ADMIN_TOKEN: &str = "totp-race-admin-token";
struct Harness {
    router: Router,
    state: AppState,
    database: chenxing_auth::sqlx::PgPool,
    key_directory: std::path::PathBuf,
    email: String,
}

/// 并发用例会同时发起多路 service 调用，每一路都要查一次 factor methods。
/// 默认的 2 个连接会把它们串成队列，Redis 侧的竞态窗口就被数据库排队掩盖了。
async fn isolated_database(database_url: &str) -> chenxing_auth::sqlx::PgPool {
    db_isolation::isolated_pool_with_max_connections("totp_factor_race", database_url, 8).await
}

async fn setup() -> Harness {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = isolated_database(&database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-totp-race-{}", Uuid::new_v4()));
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
    let email = format!("totp-race-{}@example.com", Uuid::new_v4().simple());
    // Service 层的并发测试需要直接持有 AppState，因此这里先克隆再交给 router。
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("test state")
        .with_clock(SharedClock::fixed(totp_time::centered_now()));
    let router = api::router(state.clone());
    oauth_flow::ensure_owner_bootstrapped(
        &router,
        &database,
        "totp_factor_race",
        "totp_factor_race",
    )
    .await;
    Harness {
        router,
        state,
        database,
        key_directory,
        email,
    }
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

fn csrf(cookie: &str) -> String {
    cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix("chenxing_csrf="))
        .expect("CSRF cookie")
        .to_owned()
}

async fn request_with_session(
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

#[tokio::test]
async fn parallel_authenticated_totp_confirmations_have_only_one_winner() {
    let Harness {
        router,
        state,
        database,
        key_directory,
        email,
    } = setup().await;
    let username = format!("totp-race-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;

    let login_response = request(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    assert_eq!(login_response.status(), StatusCode::OK);
    let session_cookie = pending_cookie(&login_response);
    let csrf_token = csrf(&session_cookie);
    let setup = json_body(
        request_with_session(
            &router,
            "/api/v1/auth/security/totp/enrollment/start",
            serde_json::json!({}),
            &session_cookie,
            &csrf_token,
        )
        .await,
    )
    .await;
    let totp = TOTP::from_url(setup["otpauth_url"].as_str().expect("TOTP URI")).expect("TOTP");
    let now = u64::try_from(state.clock.now().unix_timestamp()).expect("fixed test timestamp");
    let body = serde_json::json!({
        "enrollment_id": setup["enrollment_id"],
        "code": totp.generate(now)
    });
    let (first, second) = tokio::join!(
        request_with_session(
            &router,
            "/api/v1/auth/security/totp/enrollment/confirm",
            body.clone(),
            &session_cookie,
            &csrf_token,
        ),
        request_with_session(
            &router,
            "/api/v1/auth/security/totp/enrollment/confirm",
            body,
            &session_cookie,
            &csrf_token,
        )
    );
    let statuses = [first.status(), second.status()];
    assert!(statuses.contains(&StatusCode::OK), "statuses: {statuses:?}");
    assert!(
        statuses.contains(&StatusCode::UNAUTHORIZED) || statuses.contains(&StatusCode::BAD_REQUEST),
        "statuses: {statuses:?}"
    );

    let user_id: i64 = chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_totp_factors WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&database)
        .await
        .expect("factor count"),
        1
    );
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// #265：同一张 ticket 上并发 `start_totp_enrollment` 只允许一个胜者，
/// 且预留的 secret 绝不被后到的调用覆盖。
///
/// 直接打 service 层而不是 HTTP 端点，是为了让所有并发调用命中同一个 ticket
/// 与同一个 Redis 键——这正是 bug 所在的窗口。断言分两段：
///
/// 1. 胜者数量恰好为 1。先查后写的实现在这里会出现多个胜者。
/// 2. 胜者的 secret 能通过确认。这一条才真正排除「覆盖」：即使实现侥幸只返回
///    一个 `Some`，被后续写入覆盖掉的 secret 也无法完成确认，用户验证器 App 里
///    的那份密钥就永久失效了。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_enrollment_starts_reserve_one_secret_per_ticket() {
    let Harness {
        router,
        state,
        database,
        key_directory,
        email,
    } = setup().await;
    let username = format!("totp-reserve-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;
    let user_id: i64 = chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");

    let factors = state.factors.clone();
    let holder_hash = format!("holder-{}", Uuid::new_v4().simple());
    let authenticated = AuthenticatedUser::new(user_id, 0);
    let (ticket_id, _ticket) = factors
        .create_login_ticket(authenticated, vec![FactorMethod::Totp], &holder_hash)
        .await
        .expect("login ticket");

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let factors = factors.clone();
        let ticket_id = ticket_id.clone();
        let holder_hash = holder_hash.clone();
        let email = email.clone();
        tasks.push(tokio::spawn(async move {
            factors
                .start_totp_enrollment(&ticket_id, &holder_hash, &email, "Chenxing Pass")
                .await
                .expect("start TOTP enrollment")
        }));
    }
    let mut enrollments = Vec::new();
    for task in tasks {
        if let Some(enrollment) = task.await.expect("join enrollment start") {
            enrollments.push(enrollment);
        }
    }
    assert_eq!(
        enrollments.len(),
        1,
        "only one concurrent enrollment start may reserve the pending secret"
    );

    // 胜者的 secret 必须仍然是 Redis 里预留的那一份，否则确认会失败。
    let code = TOTP::from_url(enrollments[0].otpauth_url())
        .expect("winner TOTP")
        .generate_current()
        .expect("winner TOTP code");
    assert_eq!(
        factors
            .confirm_totp_enrollment(&ticket_id, &holder_hash, None, &code)
            .await
            .expect("confirm TOTP enrollment"),
        TotpConfirmation::Completed(authenticated),
        "the reserved secret must be the one that confirms"
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_totp_factors WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&database)
        .await
        .expect("factor count"),
        1
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}
