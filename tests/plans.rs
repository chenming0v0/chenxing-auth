use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chenxing_auth::sqlx::postgres::PgPoolOptions;
use chenxing_auth::{
    api,
    config::Config,
    db,
    oauth::{
        authorization::ValidatedAuthorizationRequest,
        handlers::{AuthorizationCodeIssue, issue_authorization_code_result},
        quota::QuotaConsumeResult,
        store::AuthorizationCodeStore,
    },
    plans::domain::AuthQuotaLimits,
    sessions::domain::Session,
    state::AppState,
};
use serde_json::Value;
use serial_test::serial;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN_TOKEN: &str = "plans-admin-token";

async fn test_state() -> (AppState, chenxing_auth::sqlx::PgPool, std::path::PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("PostgreSQL is required for plan tests");
    db::migrate(&database).await.expect("database migrations");
    chenxing_auth::sqlx::query("DELETE FROM plans WHERE code <> 'basic'")
        .execute(&database)
        .await
        .expect("reset custom plans");
    chenxing_auth::sqlx::query(
        "UPDATE plans SET code = 'basic', name = '基础版', description = '默认套餐',
             oauth_clients_limit = 2, daily_auth_limit = 2500, monthly_auth_limit = 50000,
             max_qps = NULL, status = 'active', is_default = TRUE, updated_at = NOW()
         WHERE code = 'basic'",
    )
    .execute(&database)
    .await
    .expect("reset basic plan");
    let key_directory = std::env::temp_dir().join(format!("chenxing-plans-{}", Uuid::new_v4()));
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
    let state = AppState::new(config).await.expect("test state");
    (state, database, key_directory)
}

async fn json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

async fn bootstrap_owner(router: &Router, suffix: &str) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("plan-owner-{suffix}"),
                        "email": format!("plan-owner-{suffix}@example.com"),
                        "password": "correct horse battery",
                    })
                    .to_string(),
                ))
                .expect("bootstrap request"),
        )
        .await
        .expect("bootstrap response");
    assert!(
        matches!(
            response.status(),
            StatusCode::CREATED | StatusCode::CONFLICT
        ),
        "unexpected bootstrap status: {}",
        response.status()
    );
}

async fn register_user(router: &Router, suffix: &str) -> i64 {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("plan-user-{suffix}"),
                        "email": format!("plan-user-{suffix}@example.com"),
                        "password": "correct horse battery",
                    })
                    .to_string(),
                ))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::CREATED);
    json(response).await["user"]["id"]
        .as_i64()
        .expect("numeric user id")
}

async fn user_session(state: &AppState, user_id: i64) -> (String, String) {
    let mut session =
        Session::new(user_id.to_string(), Duration::from_secs(3600)).expect("browser session");
    state
        .sessions
        .save(&mut session, Duration::from_secs(3600))
        .await
        .expect("persist session");
    let cookie = format!(
        "chenxing_session={}; chenxing_csrf={}",
        session.token, session.csrf_token
    );
    (cookie, session.csrf_token)
}

async fn create_owned_client(router: &Router, cookie: &str, csrf: &str, suffix: &str) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": format!("Plan Client {suffix}"),
                        "redirect_uris": ["https://plan.example/callback"],
                        "scopes": ["openid", "profile", "email"],
                    })
                    .to_string(),
                ))
                .expect("owned client request"),
        )
        .await
        .expect("owned client response");
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "owned client creation: {}",
        response.status()
    );
    json(response).await
}

async fn create_plan(
    router: &Router,
    suffix: &str,
    limits: serde_json::Map<String, Value>,
) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("code".to_owned(), Value::String(format!("plan-{suffix}")));
    body.insert("name".to_owned(), Value::String(format!("Plan {suffix}")));
    body.insert("description".to_owned(), Value::Null);
    body.insert("is_default".to_owned(), Value::Bool(false));
    body.extend(limits);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/plans")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(Value::Object(body).to_string()))
                .expect("create plan request"),
        )
        .await
        .expect("create plan response");
    assert_eq!(response.status(), StatusCode::CREATED, "create plan");
    json(response).await
}

async fn update_plan(
    router: &Router,
    plan_id: i64,
    code: &str,
    is_default: bool,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/plans/{plan_id}"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "code": code,
                        "name": "Updated plan",
                        "description": null,
                        "oauth_clients_limit": 2,
                        "daily_auth_limit": 2500,
                        "monthly_auth_limit": 50000,
                        "max_qps": null,
                        "is_default": is_default,
                    })
                    .to_string(),
                ))
                .expect("update plan request"),
        )
        .await
        .expect("update plan response");
    let status = response.status();
    (status, json(response).await)
}

async fn assign_plan(
    router: &Router,
    user_id: i64,
    plan_id: i64,
    expires_at: Option<Value>,
) -> StatusCode {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/plan"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "plan_id": plan_id, "expires_at": expires_at }).to_string(),
                ))
                .expect("assign plan request"),
        )
        .await
        .expect("assign plan response");
    response.status()
}

fn validated_request(client_id: &str, user_id: i64) -> ValidatedAuthorizationRequest {
    ValidatedAuthorizationRequest {
        client_id: client_id.to_owned(),
        redirect_uri: "https://plan.example/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        state: "plan-state".to_owned(),
        nonce: None,
        code_challenge: "plan-challenge".to_owned(),
        owner_user_id: Some(user_id),
        session_id: None,
    }
}

#[tokio::test]
#[serial]
async fn default_plan_seed_preserves_legacy_hardcoded_limits() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, _csrf) = user_session(&state, user_id).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/entitlements")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("entitlements request"),
        )
        .await
        .expect("entitlements response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["plan"]["code"], "basic");
    assert_eq!(body["plan"]["name"], "基础版");
    assert_eq!(body["plan"]["validity"], "permanent");
    let entitlements = body["entitlements"].as_array().expect("entitlements array");
    let by_key = |key: &str| {
        entitlements
            .iter()
            .find(|item| item["key"] == key)
            .unwrap_or_else(|| panic!("missing entitlement {key}"))
    };
    assert_eq!(by_key("oauth_clients")["limit"], 2);
    assert_eq!(by_key("daily_auth")["limit"], 2_500);
    assert_eq!(by_key("monthly_auth")["limit"], 50_000);
    assert!(
        entitlements.iter().all(|item| item["key"] != "max_qps"),
        "basic plan has no max_qps card"
    );

    // 管理端列表包含种子默认套餐，限额与旧硬编码一致（回归）。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/plans")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("admin plans request"),
        )
        .await
        .expect("admin plans response");
    assert_eq!(response.status(), StatusCode::OK);
    let plans = json(response).await;
    let basic = plans
        .as_array()
        .expect("plans array")
        .iter()
        .find(|plan| plan["code"] == "basic")
        .expect("seeded basic plan");
    assert_eq!(basic["oauth_clients_limit"], 2);
    assert_eq!(basic["daily_auth_limit"], 2_500);
    assert_eq!(basic["monthly_auth_limit"], 50_000);
    assert_eq!(basic["status"], "active");
    assert!(basic["is_default"].as_bool().unwrap_or(false));

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn assigned_plan_controls_client_quota_and_entitlements() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&state, user_id).await;

    let mut limits = serde_json::Map::new();
    limits.insert("oauth_clients_limit".to_owned(), Value::from(1));
    limits.insert("daily_auth_limit".to_owned(), Value::from(5));
    limits.insert("monthly_auth_limit".to_owned(), Value::from(100));
    limits.insert("max_qps".to_owned(), Value::Null);
    let plan = create_plan(&router, &suffix, limits).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("empty client list request"),
        )
        .await
        .expect("empty client list response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        json(response).await["items"]
            .as_array()
            .expect("empty client items")
            .is_empty()
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/entitlements")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("empty entitlements request"),
        )
        .await
        .expect("empty entitlements response");
    let empty_entitlements = json(response).await;
    let empty_items = empty_entitlements["entitlements"]
        .as_array()
        .expect("empty entitlements items");
    let empty_by_key = |key: &str| {
        empty_items
            .iter()
            .find(|item| item["key"] == key)
            .unwrap_or_else(|| panic!("missing entitlement {key}"))
    };
    assert_eq!(empty_by_key("daily_auth")["used"], 0);
    assert_eq!(empty_by_key("daily_auth")["limit"], 5);
    assert_eq!(empty_by_key("monthly_auth")["used"], 0);
    assert_eq!(empty_by_key("monthly_auth")["limit"], 100);

    let first = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    assert_eq!(first["quota"]["daily_limit"], 5);
    assert_eq!(first["quota"]["daily_used"], 0);
    assert_eq!(first["quota"]["monthly_limit"], 100);
    assert_eq!(first["quota"]["monthly_used"], 0);
    let second = router
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
                        "client_name": "Second Plan Client",
                        "redirect_uris": ["https://plan.example/callback"],
                        "scopes": ["openid", "profile", "email"],
                    })
                    .to_string(),
                ))
                .expect("second owned client request"),
        )
        .await
        .expect("second owned client response");
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let error = json(second).await;
    assert_eq!(error["code"], "oauth_client_quota_exceeded");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/entitlements")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("entitlements request"),
        )
        .await
        .expect("entitlements response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["plan"]["code"], format!("plan-{suffix}"));
    let entitlements = body["entitlements"].as_array().expect("entitlements array");
    let by_key = |key: &str| {
        entitlements
            .iter()
            .find(|item| item["key"] == key)
            .unwrap_or_else(|| panic!("missing entitlement {key}"))
    };
    assert_eq!(by_key("oauth_clients")["used"], 1);
    assert_eq!(by_key("oauth_clients")["limit"], 1);
    assert_eq!(by_key("daily_auth")["limit"], 5);
    assert_eq!(by_key("monthly_auth")["limit"], 100);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/oauth-clients")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("owned client list request"),
        )
        .await
        .expect("owned client list response");
    let clients = json(response).await;
    assert_eq!(clients["items"][0]["quota"]["daily_limit"], 5);
    assert_eq!(clients["items"][0]["quota"]["monthly_limit"], 100);

    let _ = first["client_id"].as_str();
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn assigned_plan_daily_and_monthly_limits_reject_authorizations() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&state, user_id).await;

    let mut limits = serde_json::Map::new();
    limits.insert("oauth_clients_limit".to_owned(), Value::from(1));
    limits.insert("daily_auth_limit".to_owned(), Value::from(2));
    limits.insert("monthly_auth_limit".to_owned(), Value::from(5));
    limits.insert("max_qps".to_owned(), Value::Null);
    let plan = create_plan(&router, &suffix, limits).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let validated = validated_request(&client_id, user_id);

    for _ in 0..2 {
        let result =
            issue_authorization_code_result(&state, user_id.to_string(), validated.clone())
                .await
                .expect("authorization within daily limit");
        assert!(matches!(result, AuthorizationCodeIssue::Redirect(_)));
    }
    let result = issue_authorization_code_result(&state, user_id.to_string(), validated)
        .await
        .expect("authorization over daily limit");
    assert!(matches!(result, AuthorizationCodeIssue::QuotaExceeded));

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn authorization_code_save_failure_refunds_consumed_quota() {
    let (mut state, _database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&state, user_id).await;

    let mut limits = serde_json::Map::new();
    limits.insert("oauth_clients_limit".to_owned(), Value::from(1));
    limits.insert("daily_auth_limit".to_owned(), Value::from(1));
    limits.insert("monthly_auth_limit".to_owned(), Value::from(5));
    limits.insert("max_qps".to_owned(), Value::Null);
    let plan = create_plan(&router, &suffix, limits).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let validated = validated_request(&client_id, user_id);

    state.authorization_codes = AuthorizationCodeStore::new(
        redis::Client::open("redis://127.0.0.1:1").expect("unavailable Redis URL"),
    );
    let failed =
        issue_authorization_code_result(&state, user_id.to_string(), validated.clone()).await;
    assert!(failed.is_err(), "authorization code persistence must fail");

    let snapshot = state
        .oauth_quotas
        .snapshot(
            &client_id,
            AuthQuotaLimits {
                daily_auth_limit: 1,
                monthly_auth_limit: Some(5),
            },
        )
        .await
        .expect("quota snapshot after refund");
    assert_eq!(snapshot.daily_used, 0);
    assert_eq!(snapshot.monthly_used, 0);

    state.authorization_codes = AuthorizationCodeStore::new(state.redis.clone());
    let retry = issue_authorization_code_result(&state, user_id.to_string(), validated)
        .await
        .expect("retry after quota refund");
    assert!(matches!(retry, AuthorizationCodeIssue::Redirect(_)));

    let snapshot = state
        .oauth_quotas
        .snapshot(
            &client_id,
            AuthQuotaLimits {
                daily_auth_limit: 1,
                monthly_auth_limit: Some(5),
            },
        )
        .await
        .expect("quota snapshot after successful retry");
    assert_eq!(snapshot.daily_used, 1);
    assert_eq!(snapshot.monthly_used, 1);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn unlimited_monthly_plan_never_rejects_authorizations() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&state, user_id).await;

    let mut limits = serde_json::Map::new();
    limits.insert("oauth_clients_limit".to_owned(), Value::from(1));
    limits.insert("daily_auth_limit".to_owned(), Value::from(10));
    limits.insert("monthly_auth_limit".to_owned(), Value::Null);
    limits.insert("max_qps".to_owned(), Value::Null);
    let plan = create_plan(&router, &suffix, limits).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    assert_eq!(client["quota"]["daily_limit"], 10);
    assert!(client["quota"]["monthly_limit"].is_null());
    let validated = validated_request(&client_id, user_id);

    for _ in 0..6 {
        let result =
            issue_authorization_code_result(&state, user_id.to_string(), validated.clone())
                .await
                .expect("monthly quota is unlimited");
        assert!(matches!(result, AuthorizationCodeIssue::Redirect(_)));
    }

    // 权益页把 monthly_auth 的 limit 渲染为 null（前端显示 ∞）。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/entitlements")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("entitlements request"),
        )
        .await
        .expect("entitlements response");
    let body = json(response).await;
    let monthly = body["entitlements"]
        .as_array()
        .expect("entitlements array")
        .iter()
        .find(|item| item["key"] == "monthly_auth")
        .expect("monthly_auth entitlement");
    assert!(monthly["limit"].is_null());
    assert_eq!(monthly["used"], 6);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn qps_limiter_rejects_requests_over_the_plan_limit() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&state, user_id).await;

    let mut limits = serde_json::Map::new();
    limits.insert("oauth_clients_limit".to_owned(), Value::from(1));
    limits.insert("daily_auth_limit".to_owned(), Value::from(1_000));
    limits.insert("monthly_auth_limit".to_owned(), Value::from(10_000));
    // 用 1 QPS 做顺序断言：第一发进入业务校验返回 400，第二发必被滑动窗口拒绝。
    // 这比并发三连更稳，也更直接验证 token 路径真正调用了 plan-backed limiter。
    limits.insert("max_qps".to_owned(), Value::from(1));
    let plan = create_plan(&router, &suffix, limits).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let client_secret = client["client_secret"]
        .as_str()
        .expect("client secret")
        .to_owned();
    let basic_credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let token_request = || {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("authorization", format!("Basic {basic_credentials}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("grant_type=authorization_code"))
            .expect("token request")
    };

    let invalid_basic_credentials = STANDARD.encode(format!("{client_id}:wrong-secret"));
    let invalid = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(
                    "authorization",
                    format!("Basic {invalid_basic_credentials}"),
                )
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=authorization_code"))
                .expect("invalid credential request"),
        )
        .await
        .expect("invalid credential response");
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);

    let first = router
        .clone()
        .oneshot(token_request())
        .await
        .expect("first token response");
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);

    let second = router
        .clone()
        .oneshot(token_request())
        .await
        .expect("second token response");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json(second).await["error"], "temporarily_unavailable");

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn entitlements_aggregate_usage_across_multiple_clients() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&state, user_id).await;

    let mut limits = serde_json::Map::new();
    limits.insert("oauth_clients_limit".to_owned(), Value::from(2));
    limits.insert("daily_auth_limit".to_owned(), Value::from(100));
    limits.insert("monthly_auth_limit".to_owned(), Value::from(1_000));
    limits.insert("max_qps".to_owned(), Value::Null);
    let plan = create_plan(&router, &suffix, limits).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let first = create_owned_client(&router, &cookie, &csrf, &format!("a-{suffix}")).await;
    let second = create_owned_client(&router, &cookie, &csrf, &format!("b-{suffix}")).await;
    let first_id = first["client_id"]
        .as_str()
        .expect("first client id")
        .to_owned();
    let second_id = second["client_id"]
        .as_str()
        .expect("second client id")
        .to_owned();

    for _ in 0..2 {
        assert_eq!(
            state
                .oauth_quotas
                .consume_with_limits(
                    &first_id,
                    AuthQuotaLimits {
                        daily_auth_limit: 100,
                        monthly_auth_limit: Some(1_000),
                    },
                )
                .await
                .expect("first client quota"),
            QuotaConsumeResult::Allowed
        );
    }
    assert_eq!(
        state
            .oauth_quotas
            .consume_with_limits(
                &second_id,
                AuthQuotaLimits {
                    daily_auth_limit: 100,
                    monthly_auth_limit: Some(1_000),
                },
            )
            .await
            .expect("second client quota"),
        QuotaConsumeResult::Allowed
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/entitlements")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("entitlements request"),
        )
        .await
        .expect("entitlements response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    let entitlements = body["entitlements"].as_array().expect("entitlements array");
    let by_key = |key: &str| {
        entitlements
            .iter()
            .find(|item| item["key"] == key)
            .unwrap_or_else(|| panic!("missing entitlement {key}"))
    };
    assert_eq!(by_key("oauth_clients")["used"], 2);
    assert_eq!(by_key("daily_auth")["used"], 3);
    assert_eq!(by_key("monthly_auth")["used"], 3);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn admin_plan_archive_restore_and_default_protection() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;

    let mut limits = serde_json::Map::new();
    limits.insert("oauth_clients_limit".to_owned(), Value::from(1));
    limits.insert("daily_auth_limit".to_owned(), Value::from(5));
    limits.insert("monthly_auth_limit".to_owned(), Value::Null);
    limits.insert("max_qps".to_owned(), Value::Null);
    let plan = create_plan(&router, &suffix, limits).await;
    let plan_id = plan["id"].as_i64().expect("plan id");

    let archive = |id: i64| {
        let router = router.clone();
        async move {
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/v1/admin/plans/{id}/archive"))
                        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                        .body(Body::empty())
                        .expect("archive request"),
                )
                .await
                .expect("archive response")
        }
    };
    assert_eq!(archive(plan_id).await.status(), StatusCode::NO_CONTENT);

    // 归档后的套餐不能再分配给新用户。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/plan"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "plan_id": plan_id, "expires_at": null }).to_string(),
                ))
                .expect("assign archived plan request"),
        )
        .await
        .expect("assign archived plan response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "plan_archived");

    let restore = || {
        let router = router.clone();
        async move {
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/v1/admin/plans/{plan_id}/restore"))
                        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                        .body(Body::empty())
                        .expect("restore request"),
                )
                .await
                .expect("restore response")
        }
    };
    assert_eq!(restore().await.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    // 默认套餐不能被归档。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/plans/1/archive")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("archive default request"),
        )
        .await
        .expect("archive default response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["code"], "default_plan_protected");

    // 列表包含归档状态。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/plans")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("admin plans request"),
        )
        .await
        .expect("admin plans response");
    let plans = json(response).await;
    let archived = plans
        .as_array()
        .expect("plans array")
        .iter()
        .find(|entry| entry["id"] == plan_id)
        .expect("created plan");
    assert_eq!(archived["status"], "active");
    assert_eq!(archived["assigned_users"], 1);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn update_cannot_unset_the_only_active_default_plan() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state);
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;

    let (status, _) = update_plan(&router, 1, "basic", true).await;
    assert_eq!(status, StatusCode::OK);

    let (status, error) = update_plan(&router, 1, &format!("updated-{suffix}"), false).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["code"], "default_plan_protected");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/plans")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("list plans request"),
        )
        .await
        .expect("list plans response");
    let plans = json(response).await;
    let plan = plans
        .as_array()
        .expect("plans array")
        .iter()
        .find(|entry| entry["id"] == 1)
        .expect("updated default plan");
    assert_eq!(plan["status"], "active");
    assert_eq!(plan["is_default"], true);

    let (status, _) = update_plan(&router, 1, "basic", true).await;
    assert_eq!(status, StatusCode::OK);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn archived_plan_cannot_become_default() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state);
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;

    let mut limits = serde_json::Map::new();
    limits.insert("oauth_clients_limit".to_owned(), Value::from(2));
    limits.insert("daily_auth_limit".to_owned(), Value::from(2_500));
    limits.insert("monthly_auth_limit".to_owned(), Value::from(50_000));
    limits.insert("max_qps".to_owned(), Value::Null);
    let plan = create_plan(&router, &suffix, limits).await;
    let plan_id = plan["id"].as_i64().expect("archived plan id");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/plans/{plan_id}/archive"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("archive plan request"),
        )
        .await
        .expect("archive plan response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let (status, error) = update_plan(&router, plan_id, &format!("archived-{suffix}"), true).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["code"], "archived_plan_default");

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn updating_plan_code_conflict_returns_409_business_error() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state);
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;

    let mut first_limits = serde_json::Map::new();
    first_limits.insert("oauth_clients_limit".to_owned(), Value::from(2));
    first_limits.insert("daily_auth_limit".to_owned(), Value::from(2_500));
    first_limits.insert("monthly_auth_limit".to_owned(), Value::from(50_000));
    first_limits.insert("max_qps".to_owned(), Value::Null);
    let first = create_plan(&router, &format!("first-{suffix}"), first_limits).await;

    let mut second_limits = serde_json::Map::new();
    second_limits.insert("oauth_clients_limit".to_owned(), Value::from(2));
    second_limits.insert("daily_auth_limit".to_owned(), Value::from(2_500));
    second_limits.insert("monthly_auth_limit".to_owned(), Value::from(50_000));
    second_limits.insert("max_qps".to_owned(), Value::Null);
    let second = create_plan(&router, &format!("second-{suffix}"), second_limits).await;

    let first_code = first["code"].as_str().expect("first plan code");
    let second_id = second["id"].as_i64().expect("second plan id");
    let (status, error) = update_plan(&router, second_id, first_code, false).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["code"], "plan_code_conflict");

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
#[serial]
async fn concurrent_default_updates_leave_one_active_default() {
    let (state, _database, key_directory) = test_state().await;
    let router = api::router(state);
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;

    let make_limits = || {
        let mut limits = serde_json::Map::new();
        limits.insert("oauth_clients_limit".to_owned(), Value::from(2));
        limits.insert("daily_auth_limit".to_owned(), Value::from(2_500));
        limits.insert("monthly_auth_limit".to_owned(), Value::from(50_000));
        limits.insert("max_qps".to_owned(), Value::Null);
        limits
    };
    let first = create_plan(&router, &format!("concurrent-a-{suffix}"), make_limits()).await;
    let second = create_plan(&router, &format!("concurrent-b-{suffix}"), make_limits()).await;
    let first_id = first["id"].as_i64().expect("first concurrent plan id");
    let second_id = second["id"].as_i64().expect("second concurrent plan id");

    let first_code = format!("default-a-{suffix}");
    let second_code = format!("default-b-{suffix}");
    let (first_update, second_update) = tokio::join!(
        update_plan(&router, first_id, &first_code, true),
        update_plan(&router, second_id, &second_code, true),
    );
    assert_eq!(first_update.0, StatusCode::OK);
    assert_eq!(second_update.0, StatusCode::OK);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/plans")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("list plans request"),
        )
        .await
        .expect("list plans response");
    let plans = json(response).await;
    let defaults = plans
        .as_array()
        .expect("plans array")
        .iter()
        .filter(|plan| plan["status"] == "active" && plan["is_default"] == true)
        .count();
    assert_eq!(defaults, 1);

    let (status, _) = update_plan(&router, 1, "basic", true).await;
    assert_eq!(status, StatusCode::OK);

    let _ = std::fs::remove_dir_all(key_directory);
}
