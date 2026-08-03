use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
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
    sessions::domain::Session,
    state::AppState,
};
use serde_json::Value;
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
    let state = AppState::new(config).expect("test state");
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
    }
}

#[tokio::test]
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

    let first = create_owned_client(&router, &cookie, &csrf, &suffix).await;
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

    let _ = first["client_id"].as_str();
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
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
        .snapshot(&client_id)
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
        .snapshot(&client_id)
        .await
        .expect("quota snapshot after successful retry");
    assert_eq!(snapshot.daily_used, 1);
    assert_eq!(snapshot.monthly_used, 1);

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
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
    limits.insert("max_qps".to_owned(), Value::from(2));
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
    let token_request = || {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}"
            )))
            .expect("token request")
    };

    // QPS 固定窗口按整秒翻页；等待到窗口中段，给并发请求留下足够时间，
    // 避免测试在边界附近跨窗口。
    let millis_into_second = time::OffsetDateTime::now_utc().millisecond() as u64;
    let wait_millis = (1_500 - millis_into_second) % 1_000;
    tokio::time::sleep(Duration::from_millis(wait_millis)).await;

    let (first, second, third) = tokio::join!(
        router.clone().oneshot(token_request()),
        router.clone().oneshot(token_request()),
        router.clone().oneshot(token_request()),
    );
    let responses = [
        first.expect("first token response"),
        second.expect("second token response"),
        third.expect("third token response"),
    ];
    let mut statuses = responses
        .iter()
        .map(|response| response.status())
        .collect::<Vec<_>>();
    statuses.sort_unstable_by_key(|status| status.as_u16());
    assert_eq!(
        statuses,
        vec![
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::TOO_MANY_REQUESTS,
        ]
    );
    for response in responses {
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(json(response).await["error"], "temporarily_unavailable");
        }
    }

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
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
                .consume_with_limits(&first_id, Some(100), Some(1_000))
                .await
                .expect("first client quota"),
            QuotaConsumeResult::Allowed
        );
    }
    assert_eq!(
        state
            .oauth_quotas
            .consume_with_limits(&second_id, Some(100), Some(1_000))
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
