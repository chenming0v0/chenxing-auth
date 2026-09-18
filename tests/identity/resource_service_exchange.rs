//! 辰星 Access Token → 资源服务会话令牌兑换端点的黑盒集成测试（Issue #709）。
//!
//! 契约（冻结）：
//! - `POST /api/v1/auth/chenxing/exchange`
//! - `Authorization: Bearer <辰星 access token>`，没有入站 interop 头；
//! - JSON body `{"device_id":"...","device_info":"...","provider":"<slug，可选>"}`；
//! - 200 body 恰好 `session_token` / `uid` / `expires_at`，`Cache-Control: no-store`；
//! - 401 `invalid_chenxing_token`：缺失 / 畸形 / 过期 / 已吊销 / restricted 服务的
//!   aud 不在 `allowed_client_ids`；
//! - 403 `insufficient_scope` / `account_not_linked` / `account_disabled`；
//! - 400 `invalid_request`：`device_id` 超过 255 字节，或多个候选服务而未指定 `provider`。
//!
//! 资源服务与绑定直接用 SQL 种进 `resource_service_providers` /
//! `resource_service_bindings`，绕过管理面校验；scope 由服务行声明（这里用
//! `termhub:access`），源码里不再硬编码任何产品 scope。被交换出的 session JWT 用
//! `oauth::token::decode_access_token` 验证签名与标准 claim，额外绑定 claim
//! （uid/binding_id/binding_version）从 JWT payload 段读取。

use axum::{
    Router,
    body::Body,
    http::{
        Request, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL},
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chenxing_auth::{
    api,
    consents::ConsentService,
    oauth::token::{decode_access_token, issue_access_token, issue_access_token_at},
    state::AppState,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{harness, http};

/// allowlist 固定 client id。per-test schema 隔离保证固定 id 不跨用例碰撞。
const ALLOWED_CLIENT_ID: &str = "termhub-exchange-client";
const SLUG: &str = "termhub";
const SCOPE: &str = "termhub:access";

struct Env {
    router: Router,
    state: AppState,
    database: chenxing_auth::sqlx::PgPool,
    #[allow(dead_code)]
    key_directory: std::path::PathBuf,
}

async fn setup(binary_name: &str) -> Env {
    let (state, database, key_directory, _admin_token, _suffix) =
        harness::HarnessBuilder::new(binary_name)
            // 原 `oauth_flow::test_state` 会放大 QPS 窗口，保持一致。
            .qps_window_override()
            .build_state()
            .await;
    let router = api::router(state.clone());
    Env {
        router,
        state,
        database,
        key_directory,
    }
}

/// 直接种一条资源服务行。`client_secret_ciphertext` 只需非空：兑换路径从不解密它。
///
/// 返回 provider id。issuer 用 slug 派生以满足 `UNIQUE (issuer)`。
async fn seed_provider_with(
    database: &chenxing_auth::sqlx::PgPool,
    slug: &str,
    scope: &str,
    access: &str,
    allowed: &[&str],
    enabled: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    chenxing_auth::sqlx::query(
        "INSERT INTO resource_service_providers
            (id, slug, display_name, issuer, client_id, client_secret_ciphertext,
             identifier_label, secret_label, identifier_sensitive,
             scope, scope_description, scope_access, allowed_client_ids, enabled)
         VALUES ($1, $2, $3, $4, $5, 'not-decrypted-by-exchange',
                 'Account', 'Password', FALSE, $6, '', $7, $8, $9)",
    )
    .bind(id)
    .bind(slug)
    .bind(format!("{slug} service"))
    .bind(format!("https://{slug}.example.test"))
    .bind(format!("chenxing-{slug}"))
    .bind(scope)
    .bind(access)
    .bind(
        allowed
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<String>>(),
    )
    .bind(enabled)
    .execute(database)
    .await
    .expect("seed resource service provider");
    id
}

/// 默认服务：slug `termhub`，scope `termhub:access`，已启用。
async fn seed_provider(
    database: &chenxing_auth::sqlx::PgPool,
    _client_id: &str,
    access: &str,
    allowed: &[&str],
) -> Uuid {
    seed_provider_with(database, SLUG, SCOPE, access, allowed, true).await
}

/// 种用户 + 固定 client_id 的 Client + 同意行。直接写 SQL 绕过注册时的 allowlist。
async fn seed_user_and_client(
    database: &chenxing_auth::sqlx::PgPool,
    suffix: &str,
    client_scopes: &[&str],
    consent_scopes: &[&str],
) -> (i64, String) {
    let username = format!("termhub-exchange-{suffix}");
    chenxing_auth::sqlx::query(
        "INSERT INTO users (username, email, canonical_email, password_hash, created_at, updated_at)
         VALUES ($1, $2, $2, 'not-used', NOW(), NOW())",
    )
    .bind(&username)
    .bind(format!("{username}@example.test"))
    .execute(database)
    .await
    .expect("insert user");
    let user_id: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(&username)
            .fetch_one(database)
            .await
            .expect("user id");
    seed_client_with_consent(
        database,
        user_id,
        ALLOWED_CLIENT_ID,
        client_scopes,
        consent_scopes,
    )
    .await;
    (user_id, ALLOWED_CLIENT_ID.to_owned())
}

/// 种一个已注册 Client 及该用户对它的同意行。
async fn seed_client_with_consent(
    database: &chenxing_auth::sqlx::PgPool,
    user_id: i64,
    client_id: &str,
    client_scopes: &[&str],
    consent_scopes: &[&str],
) {
    chenxing_auth::sqlx::query(
        "INSERT INTO oauth_clients
          (client_id, client_name, redirect_uris, scopes, auth_method, created_at)
          VALUES ($1, $2, $3::jsonb, $4::jsonb, 'none', NOW())",
    )
    .bind(client_id)
    .bind("Exchange Client")
    .bind(serde_json::json!(
        std::iter::once("https://exchange.example/callback")
            .map(|value| value.to_owned())
            .collect::<Vec<_>>()
    ))
    .bind(serde_json::json!(
        client_scopes
            .iter()
            .map(|scope| scope.to_string())
            .collect::<Vec<_>>()
    ))
    .execute(database)
    .await
    .expect("insert client");
    ConsentService::new(database.clone())
        .save(
            user_id,
            client_id,
            &consent_scopes
                .iter()
                .map(|scope| scope.to_string())
                .collect::<Vec<_>>(),
        )
        .await
        .expect("save consent");
}

fn issuer(state: &AppState) -> String {
    state
        .issuer
        .current()
        .expect("test state has a loaded issuer")
        .issuer()
        .as_str()
        .to_owned()
}

fn issue_token(state: &AppState, user_id: i64, client_id: &str, scopes: &[&str]) -> String {
    issue_access_token(
        &state.keys,
        &issuer(state),
        &user_id.to_string(),
        client_id,
        &scopes
            .iter()
            .map(|scope| scope.to_string())
            .collect::<Vec<_>>(),
        3600,
    )
    .expect("issue access token")
}

/// 已过期令牌：显式签发时刻比当前早 120s，寿命 60s，`exp` 已确定落在过去。
fn issue_expired_token(state: &AppState, user_id: i64, client_id: &str, scopes: &[&str]) -> String {
    issue_access_token_at(
        &state.keys,
        &issuer(state),
        &user_id.to_string(),
        client_id,
        &scopes
            .iter()
            .map(|scope| scope.to_string())
            .collect::<Vec<_>>(),
        60,
        OffsetDateTime::now_utc() - Duration::seconds(120),
    )
    .expect("issue expired access token")
}

/// 直接种一条 live 绑定行并返回其 id（UUID 字符串）。
///
/// 兑换只读 `snapshot_json.status`：`active` 放行，`disabled` → account_disabled，
/// 其它/缺失 → account_not_linked。令牌包密文留空，兑换不需要它。
async fn bind_row(
    database: &chenxing_auth::sqlx::PgPool,
    provider_id: Uuid,
    user_id: i64,
    uid: &str,
    account_status: &str,
) -> String {
    let id = Uuid::new_v4();
    chenxing_auth::sqlx::query(
        "INSERT INTO resource_service_bindings
            (id, provider_id, user_id, uid, issuer, generation, snapshot_json,
             created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, 1, $6::jsonb, NOW(), NOW())",
    )
    .bind(id)
    .bind(provider_id)
    .bind(user_id)
    .bind(uid)
    .bind(format!("https://{SLUG}.example.test"))
    .bind(json!({
        "schema_version": "1",
        "uid": uid,
        "status": account_status,
        "account": uid,
        "name": "Integration User",
        "fields": [],
        "subscriptions": [],
    }))
    .execute(database)
    .await
    .expect("seed binding");
    id.to_string()
}

async fn exchange_request(
    router: &Router,
    bearer: Option<&str>,
    body: Value,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/chenxing/exchange")
        .header("content-type", "application/json");
    if let Some(bearer) = bearer {
        builder = builder.header(AUTHORIZATION, format!("Bearer {bearer}"));
    }
    router
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.to_string()))
                .expect("exchange request"),
        )
        .await
        .expect("exchange response")
}

fn error_code(body: &Value) -> String {
    body["code"].as_str().unwrap_or_default().to_owned()
}

/// 不做签名校验地读取 JWT payload 段，用于断言标准 claim 之外的绑定 claim。
fn jwt_payload(token: &str) -> Value {
    let segment = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .expect("base64url jwt payload");
    serde_json::from_slice(&bytes).expect("json jwt payload")
}

fn valid_device_body() -> Value {
    json!({"device_id": "device-1", "device_info": "integration test"})
}

#[tokio::test]
async fn exchange_rejects_missing_bearer_with_401() {
    let env = setup("resource_service_exchange").await;
    let response = exchange_request(&env.router, None, valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn exchange_rejects_malformed_token_with_401() {
    let env = setup("resource_service_exchange").await;
    let response = exchange_request(&env.router, Some("not-a-jwt"), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn exchange_rejects_expired_token_with_401() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let provider_id = seed_provider(
        &env.database,
        ALLOWED_CLIENT_ID,
        "restricted",
        &[ALLOWED_CLIENT_ID],
    )
    .await;
    let (user_id, client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid", SCOPE], &[SCOPE]).await;
    let token = issue_expired_token(&env.state, user_id, &client_id, &[SCOPE]);
    bind_row(&env.database, provider_id, user_id, "termhub:701", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn exchange_rejects_audience_outside_allowlist_with_401() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let provider_id = seed_provider(
        &env.database,
        ALLOWED_CLIENT_ID,
        "restricted",
        &[ALLOWED_CLIENT_ID],
    )
    .await;
    let (user_id, _client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid", SCOPE], &[SCOPE]).await;
    // 另一个已注册、已同意 scope 的 Client：它不在服务的 allowed_client_ids 内，
    // restricted 服务必须拒绝它的令牌。
    let outside = format!("outside-allowlist-{suffix}");
    seed_client_with_consent(
        &env.database,
        user_id,
        &outside,
        &["openid", SCOPE],
        &[SCOPE],
    )
    .await;
    let token = issue_token(&env.state, user_id, &outside, &[SCOPE]);
    bind_row(&env.database, provider_id, user_id, "termhub:702", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn exchange_rejects_revoked_token_with_401() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let provider_id = seed_provider(
        &env.database,
        ALLOWED_CLIENT_ID,
        "restricted",
        &[ALLOWED_CLIENT_ID],
    )
    .await;
    let (user_id, client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid", SCOPE], &[SCOPE]).await;
    let token = issue_token(&env.state, user_id, &client_id, &[SCOPE]);
    env.state
        .revocations
        .revoke(&token, 3600)
        .await
        .expect("revoke token");
    bind_row(&env.database, provider_id, user_id, "termhub:703", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn exchange_rejects_missing_scope_with_403() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let provider_id = seed_provider(
        &env.database,
        ALLOWED_CLIENT_ID,
        "restricted",
        &[ALLOWED_CLIENT_ID],
    )
    .await;
    let (user_id, client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid"], &["openid"]).await;
    let token = issue_token(&env.state, user_id, &client_id, &["openid"]);
    bind_row(&env.database, provider_id, user_id, "termhub:704", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "insufficient_scope");
}

#[tokio::test]
async fn exchange_without_binding_returns_account_not_linked() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let _provider_id = seed_provider(
        &env.database,
        ALLOWED_CLIENT_ID,
        "restricted",
        &[ALLOWED_CLIENT_ID],
    )
    .await;
    let (user_id, client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid", SCOPE], &[SCOPE]).await;
    let token = issue_token(&env.state, user_id, &client_id, &[SCOPE]);

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "account_not_linked");
}

#[tokio::test]
async fn exchange_with_disabled_binding_returns_account_disabled() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let provider_id = seed_provider(
        &env.database,
        ALLOWED_CLIENT_ID,
        "restricted",
        &[ALLOWED_CLIENT_ID],
    )
    .await;
    let (user_id, client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid", SCOPE], &[SCOPE]).await;
    let token = issue_token(&env.state, user_id, &client_id, &[SCOPE]);
    bind_row(
        &env.database,
        provider_id,
        user_id,
        "termhub:705",
        "disabled",
    )
    .await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "account_disabled");
}

#[tokio::test]
async fn exchange_rejects_oversized_device_id_with_invalid_request() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let provider_id = seed_provider(
        &env.database,
        ALLOWED_CLIENT_ID,
        "restricted",
        &[ALLOWED_CLIENT_ID],
    )
    .await;
    let (user_id, client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid", SCOPE], &[SCOPE]).await;
    let token = issue_token(&env.state, user_id, &client_id, &[SCOPE]);
    // 绑定存在，保证唯一被拒绝的原因是 device_id 超长（>255 字节）。
    bind_row(&env.database, provider_id, user_id, "termhub:706", "active").await;

    let response = exchange_request(
        &env.router,
        Some(&token),
        json!({"device_id": "x".repeat(256), "device_info": "integration test"}),
    )
    .await;
    // 契约允许 400 或 422，两者都必须带 invalid_request。
    assert!(
        matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
        ),
        "oversized device_id must be 400/422, got {}",
        response.status()
    );
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_request");
}

#[tokio::test]
async fn exchange_success_returns_session_token_with_binding_claims() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let provider_id = seed_provider(
        &env.database,
        ALLOWED_CLIENT_ID,
        "restricted",
        &[ALLOWED_CLIENT_ID],
    )
    .await;
    let (user_id, client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid", SCOPE], &[SCOPE]).await;
    let token = issue_token(&env.state, user_id, &client_id, &[SCOPE]);
    let binding_id = bind_row(&env.database, provider_id, user_id, "termhub:777", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::OK, "exchange must succeed");
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "success response must be Cache-Control: no-store"
    );

    let body: Value = http::json_body(response).await;
    // 契约：响应体恰好这三个键，且不得出现其他令牌类型。
    let keys = body
        .as_object()
        .expect("object body")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from(["session_token", "uid", "expires_at"]),
        "success body must contain exactly session_token/uid/expires_at"
    );
    for forbidden in ["access_token", "refresh_token", "id_token"] {
        assert!(
            body.get(forbidden).is_none(),
            "success body must not contain {forbidden}"
        );
    }
    assert_eq!(body["uid"], "termhub:777");

    let session_token = body["session_token"].as_str().expect("session token");
    let expires_at = body["expires_at"].as_str().expect("expires_at rfc3339");
    let parsed = OffsetDateTime::parse(expires_at, &Rfc3339).expect("expires_at parses");
    let now = OffsetDateTime::now_utc();
    assert!(
        parsed <= now + Duration::seconds(300),
        "expires_at must be within 300s, got {expires_at}"
    );
    assert!(
        parsed > now - Duration::seconds(30),
        "expires_at must not be in the past, got {expires_at}"
    );

    // session JWT：用与生产相同的 `decode_access_token` 验证签名与标准 claim。
    let issuer = issuer(&env.state);
    let claims = decode_access_token(&env.state.keys, &issuer, &client_id, session_token)
        .expect("session token must decode as an access token");
    assert_eq!(claims.iss, issuer);
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.aud, client_id);
    assert!(
        claims.scope.split_whitespace().any(|scope| scope == SCOPE),
        "session token must carry the resource service scope"
    );
    assert!(claims.exp >= claims.iat, "exp must not precede iat");
    assert!(
        claims.exp - claims.iat <= 300,
        "session token lifetime must be <= 300s"
    );

    // 绑定 claim 不在 `AccessTokenClaims` 里，从 payload 段读取。
    let payload = jwt_payload(session_token);
    assert_eq!(payload["uid"], "termhub:777");
    assert_eq!(payload["binding_id"], binding_id);
    assert_eq!(payload["binding_version"], 1);
}

#[tokio::test]
async fn exchange_with_two_resource_scopes_requires_provider_field() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let provider_id = seed_provider(
        &env.database,
        ALLOWED_CLIENT_ID,
        "restricted",
        &[ALLOWED_CLIENT_ID],
    )
    .await;
    let other_id = seed_provider_with(
        &env.database,
        "otherhub",
        "otherhub:access",
        "public",
        &[],
        true,
    )
    .await;
    let (user_id, client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", SCOPE, "otherhub:access"],
        &[SCOPE, "otherhub:access"],
    )
    .await;
    let token = issue_token(&env.state, user_id, &client_id, &[SCOPE, "otherhub:access"]);
    bind_row(&env.database, provider_id, user_id, "termhub:801", "active").await;
    bind_row(&env.database, other_id, user_id, "otherhub:801", "active").await;

    // 两个候选、未指定 provider → 400 invalid_request。
    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_request");

    // 指定 provider 后按该服务的绑定签发。
    let response = exchange_request(
        &env.router,
        Some(&token),
        json!({"device_id": "device-1", "provider": SLUG}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = http::json_body(response).await;
    assert_eq!(body["uid"], "termhub:801");

    // 指定不在候选内的 provider → 403 insufficient_scope。
    let response = exchange_request(
        &env.router,
        Some(&token),
        json!({"device_id": "device-1", "provider": "nowhere"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "insufficient_scope");
}

#[tokio::test]
async fn exchange_public_scope_access_ignores_allowed_client_ids() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let provider_id = seed_provider(&env.database, ALLOWED_CLIENT_ID, "public", &[]).await;
    let (user_id, client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid", SCOPE], &[SCOPE]).await;
    let token = issue_token(&env.state, user_id, &client_id, &[SCOPE]);
    bind_row(&env.database, provider_id, user_id, "termhub:802", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = http::json_body(response).await;
    assert_eq!(body["uid"], "termhub:802");
}

#[tokio::test]
async fn exchange_rejects_disabled_provider_with_insufficient_scope() {
    let env = setup("resource_service_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let provider_id = seed_provider_with(
        &env.database,
        SLUG,
        SCOPE,
        "restricted",
        &[ALLOWED_CLIENT_ID],
        false,
    )
    .await;
    // 令牌同时带 openid：grant gate 收窄后仍有有效 scope，走到资源服务选择这一步；
    // 已禁用服务不在目录里 → 候选为零 → insufficient_scope。
    let (user_id, client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", SCOPE],
        &["openid", SCOPE],
    )
    .await;
    let token = issue_token(&env.state, user_id, &client_id, &["openid", SCOPE]);
    bind_row(&env.database, provider_id, user_id, "termhub:803", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = http::json_body(response).await;
    assert_eq!(error_code(&body), "insufficient_scope");
}
