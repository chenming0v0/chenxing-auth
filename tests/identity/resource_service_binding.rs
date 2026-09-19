//! 资源服务门户绑定的黑盒集成测试：真实走 `POST /api/v1/auth/resource-services/bindings`，
//! 提供方由进程内桩传输层扮演（回放 `docs/account-provider-v1/fixtures/link-session-response.json`）。
//!
//! 回归背景：线上首次联调时创建绑定 503，日志为
//! `resource_service_operations` 违反外键 `resource_service_operations_binding_fk`——
//! 操作行先于绑定行插入。此前没有任何用例驱动过这条 HTTP 路径。

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    resource_services::{
        HttpMethod, ProviderHttpRequest, ProviderHttpResponse, ProviderTransport, TransportFuture,
    },
    state::AppState,
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{harness, http};

const ADMIN_TOKEN: &str = "resource-service-binding-admin-token";
const PROVIDER_ISSUER: &str = "https://provider.example.com";
const CLIENT_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

/// 进程内提供方桩：元数据回放 `metadata.json`（管理面创建时会拉取），创建端点按
/// 请求体里的 `client_binding_id` 回放夹具；`calls` 只记录创建调用。
#[derive(Default)]
struct StubProvider {
    calls: Mutex<Vec<ProviderHttpRequest>>,
}

impl ProviderTransport for StubProvider {
    fn execute<'a>(&'a self, request: ProviderHttpRequest) -> TransportFuture<'a> {
        Box::pin(async move {
            let path = request.url.path().to_owned();
            let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
            if path == "/.well-known/account-provider" {
                return Ok(ProviderHttpResponse {
                    status: 200,
                    retry_after_seconds: None,
                    body: include_bytes!("../../docs/account-provider-v1/fixtures/metadata.json")
                        .to_vec(),
                });
            }
            self.calls.lock().expect("calls").push(request);
            if path != "/api/v1/account-provider/link-sessions" {
                return Ok(ProviderHttpResponse {
                    status: 404,
                    retry_after_seconds: None,
                    body: Vec::new(),
                });
            }
            let mut response: Value = serde_json::from_str(include_str!(
                "../../docs/account-provider-v1/fixtures/link-session-response.json"
            ))
            .expect("fixture");
            response["client_binding_id"] = body["client_binding_id"].clone();
            Ok(ProviderHttpResponse {
                status: 201,
                retry_after_seconds: None,
                body: serde_json::to_vec(&response).expect("json"),
            })
        })
    }
}

struct Env {
    router: Router,
    state: AppState,
    database: chenxing_auth::sqlx::PgPool,
    stub: Arc<StubProvider>,
    #[allow(dead_code)]
    key_directory: std::path::PathBuf,
}

async fn setup(binary_name: &str) -> Env {
    let (mut state, database, key_directory, _admin_token, _suffix) =
        harness::HarnessBuilder::new(binary_name)
            .admin_token(ADMIN_TOKEN)
            .qps_window_override()
            .build_state()
            .await;
    let stub = Arc::new(StubProvider::default());
    state.resource_services = state
        .resource_services
        .clone()
        .with_transport_override(stub.clone());
    let router = api::router(state.clone());
    Env {
        router,
        state,
        database,
        stub,
        key_directory,
    }
}

/// 走真实管理接口创建资源服务，保证 client_secret 以正式密钥加密落库。
async fn create_provider(router: &Router) -> Uuid {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/resource-services")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "slug": "demo",
                        "display_name": "Demo Service",
                        "issuer": PROVIDER_ISSUER,
                        "client_id": "chenxing-portal",
                        "client_secret": CLIENT_SECRET,
                        "scope_description": "read demo account",
                        "expected_revision": 0
                    })
                    .to_string(),
                ))
                .expect("create provider request"),
        )
        .await
        .expect("create provider response");
    let status = response.status();
    let body = http::json_body(response).await;
    assert_eq!(status, StatusCode::CREATED, "create provider: {body}");
    Uuid::parse_str(body["id"].as_str().expect("provider id")).expect("uuid")
}

async fn create_user(database: &chenxing_auth::sqlx::PgPool, suffix: &str) -> i64 {
    let username = format!("binding-{suffix}");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, created_at, updated_at)
         VALUES ($1, $2, $2, 'not-used', NOW(), NOW())",
    )
    .bind(&username)
    .bind(format!("{username}@example.test"))
    .execute(database)
    .await
    .expect("insert user");
    chenxing_auth::sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE username = $1")
        .bind(&username)
        .fetch_one(database)
        .await
        .expect("user id")
}

async fn browser_session(state: &AppState, user_id: i64) -> (String, String) {
    let mut session = chenxing_auth::sessions::domain::Session::new(
        user_id.to_string(),
        std::time::Duration::from_secs(3600),
    )
    .expect("session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("save session");
    let cookie = crate::oauth_flow::session_cookie(&session);
    (cookie, session.csrf_token.clone())
}

async fn post_binding(
    router: &Router,
    cookie: &str,
    csrf: &str,
    idempotency_key: Uuid,
    provider_id: Uuid,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/resource-services/bindings")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("idempotency-key", idempotency_key.to_string())
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "provider_id": provider_id,
                        "identifier": "pub-example-0001",
                        "secret": "priv-example-0001"
                    })
                    .to_string(),
                ))
                .expect("binding request"),
        )
        .await
        .expect("binding response")
}

#[tokio::test]
async fn create_binding_persists_binding_before_operation_and_commits() {
    let env = setup("rs-binding-create").await;
    let provider_id = create_provider(&env.router).await;
    let user_id = create_user(&env.database, "create").await;
    let (cookie, csrf) = browser_session(&env.state, user_id).await;

    let response = post_binding(&env.router, &cookie, &csrf, Uuid::new_v4(), provider_id).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = http::json_body(response).await;
    assert_eq!(body["uid"], "acct-1001");
    assert_eq!(body["provider_id"], provider_id.to_string());
    let binding_id = Uuid::parse_str(body["id"].as_str().expect("binding id")).expect("uuid");

    // 提供方桩收到的 client_binding_id 必须就是本地绑定行的 id。
    {
        let calls = env.stub.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0].method, HttpMethod::Post));
        let sent: Value = serde_json::from_slice(&calls[0].body).expect("request json");
        assert_eq!(sent["client_binding_id"], binding_id.to_string());
    }

    let (bindings, committed): (i64, i64) = chenxing_auth::sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM resource_service_bindings WHERE id = $1 AND uid = 'acct-1001'),
            (SELECT COUNT(*) FROM resource_service_operations
              WHERE binding_id = $1 AND operation_type = 'create' AND status = 'committed')",
    )
    .bind(binding_id)
    .fetch_one(&env.database)
    .await
    .expect("counts");
    assert_eq!((bindings, committed), (1, 1));
}

#[tokio::test]
async fn create_binding_replays_same_idempotency_key_without_second_provider_call() {
    let env = setup("rs-binding-replay").await;
    let provider_id = create_provider(&env.router).await;
    let user_id = create_user(&env.database, "replay").await;
    let (cookie, csrf) = browser_session(&env.state, user_id).await;
    let key = Uuid::new_v4();

    let first = post_binding(&env.router, &cookie, &csrf, key, provider_id).await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body = http::json_body(first).await;

    let second = post_binding(&env.router, &cookie, &csrf, key, provider_id).await;
    assert_eq!(second.status(), StatusCode::CREATED);
    let second_body = http::json_body(second).await;
    assert_eq!(first_body["id"], second_body["id"]);
    assert_eq!(env.stub.calls.lock().expect("calls").len(), 1);
}
