//! Issue #729：提供方终态 `account_disabled` 必须写进 live 快照的 `status`。
//!
//! 兑换只看 `snapshot_json.status`（`active` 签发 300 秒票，`disabled` 拒绝，
//! 其它当未绑定）。这里不改兑换门，只证明同步 / 刷新 / 创建把终态写进去之后，
//! 现有门不再签发。网络错误和 5xx 仍返回旧的 active 快照。

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::AUTHORIZATION},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chenxing_auth::{
    api,
    consents::ConsentService,
    oauth::token::issue_access_token,
    resource_services::{
        ProviderHttpRequest, ProviderHttpResponse, ProviderTransport, ServiceError, TransportError,
        TransportFuture,
    },
    state::AppState,
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{harness, http};

const ADMIN_TOKEN: &str = "resource-service-account-disabled-admin";
const PROVIDER_ISSUER: &str = "https://provider.example.com";
const CLIENT_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
const SCOPE: &str = "demo:access";
const OAUTH_CLIENT: &str = "account-disabled-client";
const BINARY: &str = "rs-acct-disabled";

#[derive(Clone, Copy, Default)]
enum Script {
    #[default]
    Ok,
    Disabled,
    Status502,
    Transport,
}

struct StubProvider {
    create: Mutex<Script>,
    refresh: Mutex<Script>,
    account: Mutex<Script>,
    database: chenxing_auth::sqlx::PgPool,
    /// 在 GET /account 返回之前把这条门户会话标成已撤销。
    revoke_session_on_account: Mutex<Option<i64>>,
}

impl StubProvider {
    fn new(database: chenxing_auth::sqlx::PgPool) -> Self {
        Self {
            create: Mutex::new(Script::Ok),
            refresh: Mutex::new(Script::Ok),
            account: Mutex::new(Script::Ok),
            database,
            revoke_session_on_account: Mutex::new(None),
        }
    }

    fn set_account(&self, script: Script) {
        *self.account.lock().expect("account script") = script;
    }

    fn set_refresh(&self, script: Script) {
        *self.refresh.lock().expect("refresh script") = script;
    }

    fn set_create(&self, script: Script) {
        *self.create.lock().expect("create script") = script;
    }

    async fn maybe_revoke_session(&self) {
        let Some(session_id) = *self.revoke_session_on_account.lock().expect("revoke") else {
            return;
        };
        chenxing_auth::sqlx::query(
            "UPDATE user_sessions SET revoked_at = statement_timestamp() WHERE id = $1",
        )
        .bind(session_id)
        .execute(&self.database)
        .await
        .expect("revoke portal session during account fetch");
    }
}

impl ProviderTransport for StubProvider {
    fn execute<'a>(&'a self, request: ProviderHttpRequest) -> TransportFuture<'a> {
        Box::pin(async move {
            let path = request.url.path().to_owned();
            if path == "/.well-known/account-provider" {
                return Ok(ProviderHttpResponse {
                    status: 200,
                    retry_after_seconds: None,
                    body: include_bytes!("../../docs/account-provider-v1/fixtures/metadata.json")
                        .to_vec(),
                });
            }
            if path == "/api/v1/account-provider/account" {
                self.maybe_revoke_session().await;
                let script = *self.account.lock().expect("account script");
                return scripted(script, account_ok());
            }
            if path == "/api/v1/account-provider/link-sessions/refresh" {
                let script = *self.refresh.lock().expect("refresh script");
                return scripted(
                    script,
                    ProviderHttpResponse {
                        status: 404,
                        retry_after_seconds: None,
                        body: Vec::new(),
                    },
                );
            }
            if path == "/api/v1/account-provider/link-sessions" {
                let script = *self.create.lock().expect("create script");
                let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
                return scripted(script, created_ok(&body));
            }
            Ok(ProviderHttpResponse {
                status: 404,
                retry_after_seconds: None,
                body: Vec::new(),
            })
        })
    }
}

fn scripted(
    script: Script,
    ok: ProviderHttpResponse,
) -> Result<ProviderHttpResponse, TransportError> {
    match script {
        Script::Ok => Ok(ok),
        Script::Disabled => Ok(ProviderHttpResponse {
            status: 403,
            retry_after_seconds: None,
            body: br#"{"error":{"code":"account_disabled","retryable":false}}"#.to_vec(),
        }),
        Script::Status502 => Ok(ProviderHttpResponse {
            status: 502,
            retry_after_seconds: None,
            body: br#"{"error":{"code":"provider_unavailable"}}"#.to_vec(),
        }),
        Script::Transport => Err(TransportError::Unavailable),
    }
}

fn created_ok(body: &Value) -> ProviderHttpResponse {
    let mut response: Value = serde_json::from_str(include_str!(
        "../../docs/account-provider-v1/fixtures/link-session-response.json"
    ))
    .expect("fixture");
    response["client_binding_id"] = body["client_binding_id"].clone();
    ProviderHttpResponse {
        status: 201,
        retry_after_seconds: None,
        body: serde_json::to_vec(&response).expect("json"),
    }
}

fn account_ok() -> ProviderHttpResponse {
    ProviderHttpResponse {
        status: 200,
        retry_after_seconds: None,
        body: include_bytes!("../../docs/account-provider-v1/fixtures/account-snapshot.json")
            .to_vec(),
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

struct Bound {
    env: Env,
    binding_id: Uuid,
    cookie: String,
    csrf: String,
    session_id: i64,
    token: String,
}

async fn setup(label: &str) -> Env {
    let (mut state, database, key_directory, _admin_token, _suffix) =
        harness::HarnessBuilder::new(&format!("{BINARY}-{label}"))
            .admin_token(ADMIN_TOKEN)
            .qps_window_override()
            .build_state()
            .await;
    let stub = Arc::new(StubProvider::new(database.clone()));
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
                        "scope": SCOPE,
                        "scope_description": "read demo account",
                        "scope_access": "public",
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
    let username = format!("disabled-{suffix}");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, created_at, updated_at)
         VALUES ($1, $2, $2, 'not-used', NOW(), NOW())",
    )
    .bind(&username)
    .bind(format!("{username}@example.test"))
    .execute(database)
    .await
    .expect("insert user");
    chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
        .bind(username)
        .fetch_one(database)
        .await
        .expect("user id")
}

async fn browser_session(state: &AppState, user_id: i64) -> (String, String, i64) {
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
    (cookie, session.csrf_token.clone(), session.id)
}

async fn seed_exchange_token(env: &Env, user_id: i64) -> String {
    chenxing_auth::sqlx::query(
        "INSERT INTO oauth_clients
           (client_id, client_name, redirect_uris, scopes, auth_method, created_at)
           VALUES ($1, $2, $3::jsonb, $4::jsonb, 'none', NOW())",
    )
    .bind(OAUTH_CLIENT)
    .bind("Account Disabled Client")
    .bind(json!(["https://exchange.example/callback"]))
    .bind(json!(["openid", SCOPE]))
    .execute(&env.database)
    .await
    .expect("insert client");
    ConsentService::new(env.database.clone())
        .save(
            user_id,
            OAUTH_CLIENT,
            &["openid".to_owned(), SCOPE.to_owned()],
        )
        .await
        .expect("save consent");
    let issuer = env
        .state
        .issuer
        .current()
        .expect("issuer")
        .issuer()
        .as_str()
        .to_owned();
    issue_access_token(
        &env.state.keys,
        &issuer,
        &user_id.to_string(),
        OAUTH_CLIENT,
        &["openid".to_owned(), SCOPE.to_owned()],
        3600,
    )
    .expect("issue access token")
}

async fn post_binding(
    router: &Router,
    cookie: &str,
    csrf: &str,
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
                .header("idempotency-key", Uuid::new_v4().to_string())
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

async fn post_sync(
    router: &Router,
    cookie: &str,
    csrf: &str,
    binding_id: Uuid,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/auth/resource-services/bindings/{binding_id}/sync"
                ))
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .expect("sync request"),
        )
        .await
        .expect("sync response")
}

async fn post_refresh(
    router: &Router,
    cookie: &str,
    csrf: &str,
    binding_id: Uuid,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/auth/resource-services/bindings/{binding_id}/refresh"
                ))
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::empty())
                .expect("refresh request"),
        )
        .await
        .expect("refresh response")
}

async fn bind_live(label: &str) -> Bound {
    let env = setup(label).await;
    let provider_id = create_provider(&env.router).await;
    let user_id = create_user(&env.database, label).await;
    let (cookie, csrf, session_id) = browser_session(&env.state, user_id).await;
    let response = post_binding(&env.router, &cookie, &csrf, provider_id).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = http::json_body(response).await;
    assert_eq!(body["status"], "active");
    let binding_id = Uuid::parse_str(body["id"].as_str().expect("binding id")).expect("uuid");
    let token = seed_exchange_token(&env, user_id).await;
    Bound {
        env,
        binding_id,
        cookie,
        csrf,
        session_id,
        token,
    }
}

struct StoredSnapshot {
    status: Option<String>,
    account: Option<String>,
    live: bool,
    has_ciphertext: bool,
    uid: String,
    generation: i64,
}

async fn stored_snapshot(
    database: &chenxing_auth::sqlx::PgPool,
    binding_id: Uuid,
) -> StoredSnapshot {
    let (status, account, live, has_ciphertext, uid, generation): (
        Option<String>,
        Option<String>,
        bool,
        bool,
        String,
        i64,
    ) = chenxing_auth::sqlx::query_as(
        "SELECT snapshot_json->>'status', snapshot_json->>'account',
                tombstoned_at IS NULL, token_bundle_ciphertext IS NOT NULL,
                uid, generation
         FROM resource_service_bindings WHERE id = $1",
    )
    .bind(binding_id)
    .fetch_one(database)
    .await
    .expect("binding row");
    StoredSnapshot {
        status,
        account,
        live,
        has_ciphertext,
        uid,
        generation,
    }
}

fn error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

fn jwt_payload(token: &str) -> Value {
    let segment = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .expect("base64url jwt payload");
    serde_json::from_slice(&bytes).expect("json jwt payload")
}

async fn exchange(env: &Env, token: &str) -> (StatusCode, Value) {
    let response = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/chenxing/exchange")
                .header("content-type", "application/json")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(
                    json!({"device_id": "device-1", "device_info": "integration test"}).to_string(),
                ))
                .expect("exchange request"),
        )
        .await
        .expect("exchange response");
    let status = response.status();
    let body = http::json_body(response).await;
    (status, body)
}

fn assert_issues_300s_ticket(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::OK, "exchange should issue: {body}");
    let token = body["session_token"].as_str().expect("session token");
    let payload = jwt_payload(token);
    let lifetime = payload["exp"].as_i64().expect("exp") - payload["iat"].as_i64().expect("iat");
    assert_eq!(lifetime, 300, "exchange must issue a 300s ticket");
}

fn assert_exchange_disabled(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::FORBIDDEN, "exchange body: {body}");
    assert_eq!(error_code(body), "account_disabled");
    assert!(body.get("session_token").is_none());
}

fn assert_disabled_without_tombstone(before: &StoredSnapshot, after: &StoredSnapshot) {
    assert_eq!(before.status.as_deref(), Some("active"));
    assert_eq!(after.status.as_deref(), Some("disabled"));
    assert!(after.live, "disabled must not tombstone the binding");
    assert!(
        after.has_ciphertext,
        "disabled must not clear the token bundle"
    );
    assert_eq!(after.account, before.account);
    assert_eq!(after.uid, before.uid);
    assert_eq!(
        after.generation, before.generation,
        "status write must not bump generation"
    );
}

#[tokio::test]
async fn sync_account_disabled_marks_snapshot_and_exchange_stops_issuing() {
    let bound = bind_live("sync-disabled").await;
    let before = stored_snapshot(&bound.env.database, bound.binding_id).await;
    let (status, body) = exchange(&bound.env, &bound.token).await;
    assert_issues_300s_ticket(status, &body);

    bound.env.stub.set_account(Script::Disabled);
    let response = post_sync(
        &bound.env.router,
        &bound.cookie,
        &bound.csrf,
        bound.binding_id,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "binding_revoked");

    let row = stored_snapshot(&bound.env.database, bound.binding_id).await;
    assert_disabled_without_tombstone(&before, &row);
    let (status, body) = exchange(&bound.env, &bound.token).await;
    assert_exchange_disabled(status, &body);
}

#[tokio::test]
async fn refresh_account_disabled_marks_snapshot_and_exchange_stops_issuing() {
    let bound = bind_live("refresh-disabled").await;
    let before = stored_snapshot(&bound.env.database, bound.binding_id).await;
    let (status, body) = exchange(&bound.env, &bound.token).await;
    assert_issues_300s_ticket(status, &body);

    bound.env.stub.set_refresh(Script::Disabled);
    let response = post_refresh(
        &bound.env.router,
        &bound.cookie,
        &bound.csrf,
        bound.binding_id,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "binding_revoked");

    let row = stored_snapshot(&bound.env.database, bound.binding_id).await;
    assert_disabled_without_tombstone(&before, &row);
    let failed: Option<String> = chenxing_auth::sqlx::query_scalar(
        "SELECT status FROM resource_service_operations
         WHERE binding_id = $1 AND operation_type = 'refresh'",
    )
    .bind(bound.binding_id)
    .fetch_optional(&bound.env.database)
    .await
    .expect("refresh operation");
    assert_eq!(failed.as_deref(), Some("failed"));

    let (status, body) = exchange(&bound.env, &bound.token).await;
    assert_exchange_disabled(status, &body);
}

#[tokio::test]
async fn create_account_disabled_marks_the_existing_live_row() {
    let env = setup("create-disabled").await;
    env.stub.set_create(Script::Disabled);
    let provider_id = create_provider(&env.router).await;
    let user_id = create_user(&env.database, "create-disabled").await;
    let (cookie, csrf, _session_id) = browser_session(&env.state, user_id).await;

    let response = post_binding(&env.router, &cookie, &csrf, provider_id).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "binding_revoked");

    let rows: Vec<(Uuid, Option<String>, bool, String)> = chenxing_auth::sqlx::query_as(
        "SELECT id, snapshot_json->>'status', tombstoned_at IS NULL, uid
         FROM resource_service_bindings WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&env.database)
    .await
    .expect("bindings");
    assert_eq!(
        rows.len(),
        1,
        "account_disabled must not insert another binding"
    );
    let (binding_id, status, live, uid) = &rows[0];
    assert_eq!(status.as_deref(), Some("disabled"));
    assert!(*live);
    assert_eq!(uid, "");

    let operation: Option<String> = chenxing_auth::sqlx::query_scalar(
        "SELECT status FROM resource_service_operations
         WHERE binding_id = $1 AND operation_type = 'create'",
    )
    .bind(binding_id)
    .fetch_optional(&env.database)
    .await
    .expect("create operation");
    assert_eq!(operation.as_deref(), Some("failed"));

    let token = seed_exchange_token(&env, user_id).await;
    let (status, body) = exchange(&env, &token).await;
    assert_exchange_disabled(status, &body);
}

#[tokio::test]
async fn sync_provider_5xx_keeps_active_snapshot_and_exchange_still_issues() {
    let bound = bind_live("sync-502").await;
    bound.env.stub.set_account(Script::Status502);
    let response = post_sync(
        &bound.env.router,
        &bound.cookie,
        &bound.csrf,
        bound.binding_id,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = http::json_body(response).await;
    assert_eq!(body["status"], "active");

    let row = stored_snapshot(&bound.env.database, bound.binding_id).await;
    assert_eq!(row.status.as_deref(), Some("active"));
    assert!(row.live);
    assert!(row.has_ciphertext);
    let (status, body) = exchange(&bound.env, &bound.token).await;
    assert_issues_300s_ticket(status, &body);
}

#[tokio::test]
async fn sync_transport_error_keeps_active_snapshot_and_exchange_still_issues() {
    let bound = bind_live("sync-transport").await;
    bound.env.stub.set_account(Script::Transport);
    let response = post_sync(
        &bound.env.router,
        &bound.cookie,
        &bound.csrf,
        bound.binding_id,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = http::json_body(response).await;
    assert_eq!(body["status"], "active");

    let row = stored_snapshot(&bound.env.database, bound.binding_id).await;
    assert_eq!(row.status.as_deref(), Some("active"));
    let (status, body) = exchange(&bound.env, &bound.token).await;
    assert_issues_300s_ticket(status, &body);
}

#[tokio::test]
async fn refresh_provider_5xx_keeps_active_snapshot_and_exchange_still_issues() {
    let bound = bind_live("refresh-502").await;
    bound.env.stub.set_refresh(Script::Status502);
    let response = post_refresh(
        &bound.env.router,
        &bound.cookie,
        &bound.csrf,
        bound.binding_id,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "provider_unavailable");

    let row = stored_snapshot(&bound.env.database, bound.binding_id).await;
    assert_eq!(row.status.as_deref(), Some("active"));
    assert!(row.has_ciphertext);
    let (status, body) = exchange(&bound.env, &bound.token).await;
    assert_issues_300s_ticket(status, &body);
}

#[tokio::test]
async fn sync_account_disabled_persists_when_portal_session_is_revoked_mid_call() {
    let bound = bind_live("sync-session").await;
    let before = stored_snapshot(&bound.env.database, bound.binding_id).await;
    *bound
        .env
        .stub
        .revoke_session_on_account
        .lock()
        .expect("revoke") = Some(bound.session_id);
    bound.env.stub.set_account(Script::Disabled);

    let response = post_sync(
        &bound.env.router,
        &bound.cookie,
        &bound.csrf,
        bound.binding_id,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "binding_revoked");

    let revoked: bool = chenxing_auth::sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM user_sessions WHERE id = $1",
    )
    .bind(bound.session_id)
    .fetch_one(&bound.env.database)
    .await
    .expect("session row");
    assert!(revoked, "the portal session must already be revoked");

    let row = stored_snapshot(&bound.env.database, bound.binding_id).await;
    assert_disabled_without_tombstone(&before, &row);
    let (status, body) = exchange(&bound.env, &bound.token).await;
    assert_exchange_disabled(status, &body);
}

async fn binding_provider_id(database: &chenxing_auth::sqlx::PgPool, binding_id: Uuid) -> Uuid {
    chenxing_auth::sqlx::query_scalar(
        "SELECT provider_id FROM resource_service_bindings WHERE id = $1",
    )
    .bind(binding_id)
    .fetch_one(database)
    .await
    .expect("provider id")
}

/// 只推进 `revision`。不是 `lock_provider`，也不锁绑定行。
async fn bump_provider_revision(database: &chenxing_auth::sqlx::PgPool, provider_id: Uuid) {
    chenxing_auth::sqlx::query(
        "UPDATE resource_service_providers SET revision = revision + 1 WHERE id = $1",
    )
    .bind(provider_id)
    .execute(database)
    .await
    .expect("bump provider revision");
}

#[tokio::test]
async fn account_disabled_second_write_lands_when_provider_revision_advances() {
    let bound = bind_live("revision-retry").await;
    let before = stored_snapshot(&bound.env.database, bound.binding_id).await;
    let provider_id = binding_provider_id(&bound.env.database, bound.binding_id).await;
    let database = bound.env.database.clone();
    let calls = AtomicUsize::new(0);

    bound
        .env
        .state
        .resource_services
        .record_account_disabled_with_probe(bound.binding_id, &mut || {
            let database = database.clone();
            let call = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                // 第一次条件更新前推进 revision，让 WHERE 落空；第二次读到新值再写。
                if call == 0 {
                    bump_provider_revision(&database, provider_id).await;
                }
            }
        })
        .await
        .expect("second write lands");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "first update must miss");

    let row = stored_snapshot(&bound.env.database, bound.binding_id).await;
    assert_disabled_without_tombstone(&before, &row);
    let (status, body) = exchange(&bound.env, &bound.token).await;
    assert_exchange_disabled(status, &body);
}

#[tokio::test]
async fn account_disabled_errors_when_snapshot_write_misses_twice() {
    let bound = bind_live("revision-miss").await;
    let before = stored_snapshot(&bound.env.database, bound.binding_id).await;
    let provider_id = binding_provider_id(&bound.env.database, bound.binding_id).await;
    let database = bound.env.database.clone();
    let calls = AtomicUsize::new(0);

    let error = bound
        .env
        .state
        .resource_services
        .record_account_disabled_with_probe(bound.binding_id, &mut || {
            let database = database.clone();
            calls.fetch_add(1, Ordering::SeqCst);
            async move {
                bump_provider_revision(&database, provider_id).await;
            }
        })
        .await
        .expect_err("two misses must not report success");
    assert!(matches!(error, ServiceError::Conflict));
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let row = stored_snapshot(&bound.env.database, bound.binding_id).await;
    assert_eq!(row.status, before.status);
    assert_eq!(row.account, before.account);
    assert_eq!(row.uid, before.uid);
    assert_eq!(row.generation, before.generation);
    assert_eq!(row.live, before.live);
    assert_eq!(row.has_ciphertext, before.has_ciphertext);
    let (status, body) = exchange(&bound.env, &bound.token).await;
    assert_issues_300s_ticket(status, &body);
}
