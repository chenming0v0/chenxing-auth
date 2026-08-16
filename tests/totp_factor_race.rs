use std::sync::Arc;

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
use redis::AsyncCommands;
use tokio::sync::Barrier;
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
    config.redis_keyspace = chenxing_auth::redis_keyspace::RedisKeyspace::new(&format!(
        "totp-factor-race-{}",
        Uuid::new_v4().simple()
    ))
    .expect("test Redis namespace");
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

async fn redis_key_exists(key: &str) -> bool {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let mut connection = redis::Client::open(redis_url)
        .expect("Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    connection.exists(key).await.expect("Redis key existence")
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
    let start_response = request_with_session(
        &router,
        "/api/v1/auth/security/totp/enrollment/start",
        serde_json::json!({}),
        &session_cookie,
        &csrf_token,
    )
    .await;
    assert_eq!(
        start_response.status(),
        StatusCode::OK,
        "enrollment start failed: {:?}",
        start_response.status()
    );
    let setup = json_body(start_response).await;
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

/// 两张首因子 ticket 使用不同 TOTP timestep，绕过同一时间步的 replay claim，
/// 并通过 barrier 并发确认。这覆盖 legacy/first-factor ticket 兼容路径的竞争：
/// 数据库原子边界必须只允许一个胜者，且两张 ticket 和 pending secret 都必须被清掉。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_first_factor_tickets_have_only_one_winner() {
    let Harness {
        router,
        state,
        database,
        key_directory,
        email,
    } = setup().await;
    let username = format!("totp-first-factor-race-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    create_user(&router, &username, &email, password).await;
    let user_id: i64 = chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    let authenticated = AuthenticatedUser::new(user_id, 0);

    // 使用对齐到 30 秒边界的固定基准时间，确保时间步计算确定性。
    // 两个码分别在 T 和 T+30 生成，验证时钟在 T+15（两步的中点），
    // 此时 current_step = T/30，验证窗口 [T/30-1, T/30, T/30+1] 覆盖两个码。
    let aligned_base = time::OffsetDateTime::from_unix_timestamp(1700000000).expect("fixed base");
    let first_now = aligned_base;
    let second_now = first_now + time::Duration::seconds(30);
    let verification_time = first_now + time::Duration::seconds(15);

    // 两个 enrollment 用不同时间步生成不同的 TOTP 码，绕过 replay claim
    let first_enrollment_factors = state
        .clone()
        .with_clock(SharedClock::fixed(first_now))
        .factors;
    let second_enrollment_factors = state
        .clone()
        .with_clock(SharedClock::fixed(second_now))
        .factors;

    // 但两个 confirmation 必须用同一个共享时钟，否则各自的固定时钟会让对方的码失效
    let shared_confirmation_clock = SharedClock::fixed(verification_time);
    let first_confirm_factors = state
        .clone()
        .with_clock(shared_confirmation_clock.clone())
        .factors;
    let second_confirm_factors = state.clone().with_clock(shared_confirmation_clock).factors;

    let first_holder = format!("first-holder-{}", Uuid::new_v4().simple());
    let second_holder = format!("second-holder-{}", Uuid::new_v4().simple());
    let (first_ticket, _) = first_enrollment_factors
        .create_login_ticket(authenticated, vec![FactorMethod::Totp], &first_holder)
        .await
        .expect("first login ticket");
    let (second_ticket, _) = second_enrollment_factors
        .create_login_ticket(authenticated, vec![FactorMethod::Totp], &second_holder)
        .await
        .expect("second login ticket");
    let first_enrollment = first_enrollment_factors
        .start_totp_enrollment(&first_ticket, &first_holder, &email, "Chenxing Pass")
        .await
        .expect("first TOTP enrollment")
        .expect("first pending secret");
    let second_enrollment = second_enrollment_factors
        .start_totp_enrollment(&second_ticket, &second_holder, &email, "Chenxing Pass")
        .await
        .expect("second TOTP enrollment")
        .expect("second pending secret");
    let first_code = TOTP::from_url(first_enrollment.otpauth_url())
        .expect("first TOTP")
        .generate(u64::try_from(first_now.unix_timestamp()).expect("first timestamp"));
    let second_code = TOTP::from_url(second_enrollment.otpauth_url())
        .expect("second TOTP")
        .generate(u64::try_from(second_now.unix_timestamp()).expect("second timestamp"));

    let start = Arc::new(Barrier::new(3));
    let first_start = start.clone();
    let first_task = tokio::spawn({
        let first_confirm_factors = first_confirm_factors.clone();
        let first_ticket = first_ticket.clone();
        let first_holder = first_holder.clone();
        async move {
            first_start.wait().await;
            let result = first_confirm_factors
                .confirm_totp_enrollment(&first_ticket, &first_holder, None, &first_code)
                .await
                .expect("first confirmation");
            (first_ticket, first_holder, result)
        }
    });
    let second_start = start.clone();
    let second_task = tokio::spawn({
        let second_confirm_factors = second_confirm_factors.clone();
        let second_ticket = second_ticket.clone();
        let second_holder = second_holder.clone();
        async move {
            second_start.wait().await;
            let result = second_confirm_factors
                .confirm_totp_enrollment(&second_ticket, &second_holder, None, &second_code)
                .await
                .expect("second confirmation");
            (second_ticket, second_holder, result)
        }
    });

    start.wait().await;
    let (first_outcome, second_outcome) = tokio::join!(first_task, second_task);
    let outcomes = [
        first_outcome.expect("join first confirmation"),
        second_outcome.expect("join second confirmation"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, _, result)| matches!(*result, TotpConfirmation::Completed(_)))
            .count(),
        1,
        "exactly one persistence contender must complete"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, _, result)| matches!(*result, TotpConfirmation::InvalidTicket))
            .count(),
        1,
        "the persistence loser must be invalidated"
    );

    let loser = outcomes
        .iter()
        .find(|(_, _, result)| matches!(*result, TotpConfirmation::InvalidTicket))
        .expect("losing confirmation");
    assert!(
        state
            .factors
            .user_id_for_ticket(&loser.0, &loser.1)
            .await
            .expect("look up losing ticket")
            .is_none(),
        "the losing ticket must not remain reusable"
    );
    for (ticket_id, _, _) in &outcomes {
        assert!(
            !redis_key_exists(
                &state
                    .config
                    .redis_keyspace
                    .key(&format!("chenxing:auth:totp-setup:{ticket_id}"))
            )
            .await,
            "neither winner nor loser may leave a pending TOTP secret"
        );
    }

    let total_factors: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT
             (SELECT COUNT(*) FROM user_totp_factors WHERE user_id = $1) +
             (SELECT COUNT(*) FROM user_passkeys WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_one(&database)
    .await
    .expect("total factor count");
    assert_eq!(
        total_factors, 1,
        "the loser must not create a second factor"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("user cleanup");

    // 清理两个 TOTP replay claim 键，避免跨测试运行污染（Redis 实例在测试间共享）
    let redis = redis::Client::open(
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned()),
    )
    .expect("redis client");
    let mut conn = redis
        .get_multiplexed_async_connection()
        .await
        .expect("redis connection");
    let first_step = u64::try_from(first_now.unix_timestamp()).expect("first timestamp") / 30;
    let second_step = u64::try_from(second_now.unix_timestamp()).expect("second timestamp") / 30;
    let _: () = redis::cmd("DEL")
        .arg(
            state
                .config
                .redis_keyspace
                .key(&format!("chenxing:auth:totp-used:{user_id}:{first_step}")),
        )
        .arg(
            state
                .config
                .redis_keyspace
                .key(&format!("chenxing:auth:totp-used:{user_id}:{second_step}")),
        )
        .query_async(&mut conn)
        .await
        .expect("clear replay claims");

    let _ = std::fs::remove_dir_all(key_directory);
}
