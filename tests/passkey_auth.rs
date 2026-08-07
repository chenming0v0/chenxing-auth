use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::auth_limiter::FailureDimension;
use chenxing_auth::{api, config::Config, state::AppState};
use redis::AsyncCommands;
use serial_test::serial;
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
    let database = db_isolation::isolated_pool("passkey_auth", &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-passkey-{}", Uuid::new_v4()));
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
    let email = format!("passkey-{}@example.com", Uuid::new_v4().simple());
    let router = api::router(
        AppState::new_with_pool(config, database.clone())
            .await
            .expect("test state"),
    );
    oauth_flow::ensure_owner_bootstrapped(&router, "passkey_auth").await;
    (router, database, key_directory, email)
}

async fn json_response(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn post(router: &Router, uri: &str, body: serde_json::Value) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response")
}

async fn post_with_cookie(
    router: &Router,
    uri: &str,
    body: serde_json::Value,
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
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response")
}

fn cookie_header(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().expect("cookie pair"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn cookie_value(cookie: &str, name: &str) -> String {
    cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix(&format!("{name}=")))
        .expect("cookie value")
        .to_owned()
}

/// 逐个 ticket 的 Passkey 失败上限直接取自限流域模型，避免测试与实现漂移。
fn ticket_failure_limit() -> usize {
    FailureDimension::Ticket.limit() as usize
}

fn bogus_registration_credential() -> serde_json::Value {
    serde_json::json!({
        "id": "",
        "rawId": "",
        "response": {"attestationObject": "", "clientDataJSON": ""},
        "type": "public-key"
    })
}

async fn create_user(router: &Router, email: &str) -> String {
    let username = format!("passkey-limit-{}", Uuid::new_v4().simple());
    let response = post(
        router,
        "/api/v1/users",
        serde_json::json!({
            "username": username,
            "email": email,
            "password": "correct horse battery"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    username
}

async fn login_ticket(router: &Router, username: &str) -> (String, String) {
    let response = post(
        router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": "correct horse battery"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let cookie = cookie_header(&response);
    assert!(json_response(response).await.get("login_ticket").is_none());
    (
        cookie_value(&cookie, "chenxing_login_ticket"),
        cookie,
    )
}

/// 在一个 ticket 上耗尽 Passkey 注册失败额度，返回每次尝试的状态码。
async fn exhaust_ticket_failures(router: &Router, ticket: &(String, String)) -> Vec<StatusCode> {
    let response = post_with_cookie(
        router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut statuses = Vec::new();
    for _ in 0..ticket_failure_limit() {
        let response = post_with_cookie(
            router,
            "/api/v1/auth/passkeys/register/finish",
            serde_json::json!({
                "credential": bogus_registration_credential()
            }),
            &ticket.1,
        )
        .await;
        statuses.push(response.status());
    }
    statuses
}

async fn mfa_failure_reasons(
    database: &chenxing_auth::sqlx::PgPool,
    user_id: i64,
) -> Vec<(String, String)> {
    chenxing_auth::sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT actor_type, metadata->>'reason' FROM audit_events
         WHERE action = 'mfa_failure' AND actor_user_id = $1
         ORDER BY id ASC",
    )
    .bind(user_id)
    .fetch_all(database)
    .await
    .expect("mfa_failure audit events")
    .into_iter()
    .map(|(actor_type, reason)| (actor_type, reason.unwrap_or_default()))
    .collect()
}

async fn user_id_for_email(database: &chenxing_auth::sqlx::PgPool, email: &str) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(database)
        .await
        .expect("user lookup")
}

async fn cleanup_user(database: &chenxing_auth::sqlx::PgPool, user_id: i64) {
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(database)
        .await
        .expect("user cleanup");
}

#[tokio::test]
#[serial(passkey_auth)]
async fn passkey_registration_start_returns_creation_challenge_for_login_ticket() {
    let (router, database, key_directory, email) = setup().await;
    let username = format!("passkey-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    let response = post(
        &router,
        "/api/v1/users",
        serde_json::json!({"username": username, "email": email, "password": password}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = post(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    let ticket = {
        let cookie = cookie_header(&response);
        assert!(json_response(response).await.get("login_ticket").is_none());
        (cookie_value(&cookie, "chenxing_login_ticket"), cookie)
    };

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await;
    assert!(body["publicKey"]["challenge"].as_str().is_some());
    assert!(body["publicKey"]["rp"]["id"].as_str().is_some());
    assert!(body["session_id"].is_null());

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/finish",
        serde_json::json!({
            "credential": {
                "id": "",
                "rawId": "",
                "response": {"attestationObject": "", "clientDataJSON": ""},
                "type": "public-key"
            }
        }),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/authentication/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial(passkey_auth)]
async fn passkey_registration_uses_updated_settings_and_keeps_start_snapshot() {
    let (router, database, key_directory, email) = setup().await;
    let username = format!("passkey-settings-{}", Uuid::new_v4().simple());
    let password = "correct horse battery";
    let old_setting = serde_json::json!({
        "enabled": true,
        "rp_name": "Old RP",
        "rp_id": "example.com",
        "user_verification": "required",
        "authenticator_attachment": "platform",
        "allow_insecure_origin": false,
        "allowed_origins": ["https://login.example.com"]
    });
    chenxing_auth::sqlx::query(
        "INSERT INTO app_settings (setting_key, setting_value, updated_at)
         VALUES ('passkey', $1, NOW())
         ON CONFLICT (setting_key) DO UPDATE
         SET setting_value = EXCLUDED.setting_value, updated_at = EXCLUDED.updated_at",
    )
    .bind(old_setting.to_string())
    .execute(&database)
    .await
    .expect("old passkey setting");

    let response = post(
        &router,
        "/api/v1/users",
        serde_json::json!({"username": username, "email": email, "password": password}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let login_response = post(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    let ticket = {
        let cookie = cookie_header(&login_response);
        assert!(json_response(login_response).await.get("login_ticket").is_none());
        (cookie_value(&cookie, "chenxing_login_ticket"), cookie)
    };
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge = json_response(response).await;
    assert_eq!(challenge["publicKey"]["rp"]["name"], "Old RP");
    assert_eq!(challenge["publicKey"]["rp"]["id"], "example.com");
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["authenticatorAttachment"],
        "platform"
    );

    let new_setting = serde_json::json!({
        "enabled": true,
        "rp_name": "New RP",
        "rp_id": "example.com",
        "user_verification": "preferred",
        "authenticator_attachment": "cross_platform",
        "allow_insecure_origin": true,
        "allowed_origins": ["http://new.example.com"]
    });
    chenxing_auth::sqlx::query(
        "UPDATE app_settings SET setting_value = $1, updated_at = NOW()
         WHERE setting_key = 'passkey'",
    )
    .bind(new_setting.to_string())
    .execute(&database)
    .await
    .expect("new passkey setting");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = redis::Client::open(redis_url).expect("Redis client");
    let mut connection = redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let pending: serde_json::Value = serde_json::from_str(
        &connection
            .get::<_, String>(format!("chenxing:auth:passkey-registration:{}", ticket.0))
            .await
            .expect("registration snapshot"),
    )
    .expect("registration snapshot JSON");
    assert_eq!(pending["settings"]["rp_name"], "Old RP");
    assert_eq!(
        pending["settings"]["allowed_origins"],
        serde_json::json!(["https://login.example.com"])
    );

    let response = post(
        &router,
        "/api/v1/auth/login",
        serde_json::json!({"identifier": username, "password": password}),
    )
    .await;
    let second_cookie = cookie_header(&response);
    let _second_pending = json_response(response).await;
    let second_ticket = (
        cookie_value(&second_cookie, "chenxing_login_ticket"),
        second_cookie,
    );
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &second_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge = json_response(response).await;
    assert_eq!(challenge["publicKey"]["rp"]["name"], "New RP");
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["userVerification"],
        "preferred"
    );
    assert_eq!(
        challenge["publicKey"]["authenticatorSelection"]["authenticatorAttachment"],
        "cross-platform"
    );
    let pending: serde_json::Value = serde_json::from_str(
        &connection
            .get::<_, String>(format!(
                "chenxing:auth:passkey-registration:{}",
                second_ticket.0
            ))
            .await
            .expect("updated registration snapshot"),
    )
    .expect("updated registration snapshot JSON");
    assert_eq!(pending["settings"]["allow_insecure_origin"], true);
    assert_eq!(
        pending["settings"]["allowed_origins"],
        serde_json::json!(["http://new.example.com"])
    );

    chenxing_auth::sqlx::query("DELETE FROM app_settings WHERE setting_key = 'passkey'")
        .execute(&database)
        .await
        .expect("passkey setting cleanup");
    let user_id: (i64,) = chenxing_auth::sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&database)
        .await
        .expect("user lookup");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.0)
        .execute(&database)
        .await
        .expect("user cleanup");
    let _: usize = connection
        .del(format!("chenxing:auth:passkey-registration:{}", ticket.0))
        .await
        .expect("old snapshot cleanup");
    let _: usize = connection
        .del(format!(
            "chenxing:auth:passkey-registration:{}",
            second_ticket.0
        ))
        .await
        .expect("new snapshot cleanup");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial(passkey_auth)]
async fn passkey_finish_failures_are_rate_limited_and_invalidate_the_ticket() {
    let (router, database, key_directory, email) = setup().await;
    let username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;
    let ticket = login_ticket(&router, &username).await;

    // 阈值内的失败仍然按“凭据无效”处理，不会被限流提前拒绝。
    let statuses = exhaust_ticket_failures(&router, &ticket).await;
    assert!(
        statuses
            .iter()
            .all(|status| *status == StatusCode::UNAUTHORIZED),
        "expected every in-window failure to stay 401, got {statuses:?}"
    );

    // ticket 维度达阈值后 ticket 已被失效，后续请求连挂起状态都不复存在。
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/finish",
        serde_json::json!({
            "credential": bogus_registration_credential()
        }),
        &ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_response(response).await["code"],
        "invalid_login_ticket"
    );

    // mfa_failure 审计事件必须带真实 actor_id，而不是写死的 anonymous。
    let events = mfa_failure_reasons(&database, user_id).await;
    assert_eq!(events.len(), ticket_failure_limit());
    assert!(
        events.iter().all(|(actor_type, _)| actor_type == "user"),
        "expected user actor_type on every mfa_failure event, got {events:?}"
    );
    let reasons: Vec<&str> = events.iter().map(|(_, reason)| reason.as_str()).collect();
    assert_eq!(
        reasons.last().copied(),
        Some("passkey_rate_limited"),
        "expected the threshold failure to be recorded as rate limited, got {reasons:?}"
    );
    assert!(
        reasons[..ticket_failure_limit() - 1]
            .iter()
            .all(|reason| *reason == "passkey_invalid"),
        "expected sub-threshold failures to stay passkey_invalid, got {reasons:?}"
    );

    cleanup_user(&database, user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial(passkey_auth)]
async fn passkey_start_endpoints_reject_before_touching_passkey_storage() {
    let (router, database, key_directory, email) = setup().await;
    let username = create_user(&router, &email).await;
    let user_id = user_id_for_email(&database, &email).await;

    let other_email = format!("passkey-other-{}@example.com", Uuid::new_v4().simple());
    let other_username = create_user(&router, &other_email).await;
    let other_user_id = user_id_for_email(&database, &other_email).await;

    // 账号维度上限高于单个 ticket 上限，需要多个 ticket 才能把账号额度耗尽。
    // spare_ticket 必须在耗尽之前签发：账号被限流后 /auth/login 自身也会被拒绝。
    let tickets_to_exhaust_account =
        (FailureDimension::Account.limit() as usize).div_ceil(ticket_failure_limit());
    let mut burn_tickets = Vec::new();
    for _ in 0..tickets_to_exhaust_account {
        burn_tickets.push(login_ticket(&router, &username).await);
    }
    let spare_ticket = login_ticket(&router, &username).await;
    let other_ticket = login_ticket(&router, &other_username).await;

    for ticket in &burn_tickets {
        exhaust_ticket_failures(&router, ticket).await;
    }

    // 账号维度耗尽后，challenge 端点必须在 list_passkeys 之前就拒绝。该账号没有任何
    // Passkey，若限流检查在数据库查询之后才生效，这里会退化成 400 invalid_login_ticket。
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/authentication/start",
        serde_json::json!({}),
        &spare_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_response(response).await["code"], "invalid_factor");

    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &spare_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 限流按账号隔离：另一个账号的成功路径不受这些失败影响。
    let response = post_with_cookie(
        &router,
        "/api/v1/auth/passkeys/register/start",
        serde_json::json!({}),
        &other_ticket.1,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        mfa_failure_reasons(&database, other_user_id)
            .await
            .is_empty(),
        "unrelated account must not accumulate mfa_failure events"
    );

    cleanup_user(&database, user_id).await;
    cleanup_user(&database, other_user_id).await;
    let _ = std::fs::remove_dir_all(key_directory);
}
