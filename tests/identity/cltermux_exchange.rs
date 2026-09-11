//! Chenxing → CLtermux 会话交换端点的黑盒集成测试（Issue #709）。
//!
//! 契约（冻结）：
//! - `POST /api/v1/auth/chenxing/exchange`
//! - `Authorization: Bearer <辰星 access token>`，没有入站 interop 头；
//! - JSON body `{"device_id":"...","device_info":"..."}`；
//! - 200 body 恰好 `session_token` / `uid` / `expires_at`，`Cache-Control: no-store`；
//! - 401 `invalid_chenxing_token`：缺失 / 畸形 / 过期 / 已吊销 / aud 不在 allowlist；
//! - 403 `insufficient_scope` / `account_not_linked` / `account_disabled`；
//! - 400/422 `invalid_request`：`device_id` 超过 255 字节。
//!
//! 这些用例只通过 HTTP 与数据库种子驱动端点，不依赖 src 内部实现；被交换出的
//! session JWT 用 `oauth::token::decode_access_token` 验证签名与标准 claim，
//! 额外绑定 claim（uid/binding_id/binding_version）从 JWT payload 段读取。

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
    config::CltermuxConfig,
    consents::ConsentService,
    oauth::token::{decode_access_token, issue_access_token, issue_access_token_at},
    state::AppState,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt;
use uuid::Uuid;

use crate::oauth_flow;

const INBOUND_TOKEN: &str = "cltermux-inbound-token-0123456789abcdef";
/// allowlist 固定 client id。per-test schema 隔离保证固定 id 不跨用例碰撞。
const ALLOWED_CLIENT_ID: &str = "cltermux-exchange-client";

struct Env {
    router: Router,
    state: AppState,
    database: chenxing_auth::sqlx::PgPool,
    #[allow(dead_code)]
    key_directory: std::path::PathBuf,
}

async fn setup(binary_name: &str) -> Env {
    let (mut state, database, key_directory) = oauth_flow::test_state(binary_name).await;
    let config = cltermux_config();
    state
        .settings
        .import_legacy_account_provider(&config)
        .await
        .expect("import legacy cltermux provider");
    state.config.cltermux = Some(config);
    let router = api::router(state.clone());
    Env {
        router,
        state,
        database,
        key_directory,
    }
}

fn cltermux_config() -> CltermuxConfig {
    CltermuxConfig {
        base_url: url::Url::parse("https://cltermux.example.com/").expect("static base url"),
        outbound_token: "cltermux-outbound-token-0123456789abcdef".to_owned(),
        inbound_token_digest: Sha256::digest(INBOUND_TOKEN.as_bytes()).to_vec(),
        allowed_client_ids: vec![ALLOWED_CLIENT_ID.to_owned()],
    }
}

/// 种用户 + 固定 client_id 的 Client + 同意行，与 `cltermux_resolve` 保持一致。
async fn seed_user_and_client(
    database: &chenxing_auth::sqlx::PgPool,
    suffix: &str,
    client_scopes: &[&str],
    consent_scopes: &[&str],
) -> (i64, String) {
    let username = format!("cltermux-exchange-{suffix}");
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

    chenxing_auth::sqlx::query(
        "INSERT INTO oauth_clients
          (client_id, client_name, redirect_uris, scopes, auth_method, created_at)
          VALUES ($1, $2, $3::jsonb, $4::jsonb, 'none', NOW())",
    )
    .bind(ALLOWED_CLIENT_ID)
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
            ALLOWED_CLIENT_ID,
            &consent_scopes
                .iter()
                .map(|scope| scope.to_string())
                .collect::<Vec<_>>(),
        )
        .await
        .expect("save consent");
    (user_id, ALLOWED_CLIENT_ID.to_owned())
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

/// 直接种绑定行并返回其 id。快照用最小 `'{}'::jsonb`，与 resolve 测试一致。
async fn bind_row(
    database: &chenxing_auth::sqlx::PgPool,
    user_id: i64,
    uid: &str,
    account_status: &str,
) -> String {
    let id = format!("link_{}", Uuid::new_v4().simple());
    chenxing_auth::sqlx::query(
        "INSERT INTO linked_accounts
            (id, user_id, provider_slug, kind, uid, subject, account_status, snapshot_json,
             linked_at, last_attempt_at, last_success_at, sync_status)
         VALUES ($1, $2, 'cltermux', 'service_account', $3, $3, $4, '{}'::jsonb,
                 NOW(), NOW(), NOW(), 'success')",
    )
    .bind(&id)
    .bind(user_id)
    .bind(uid)
    .bind(account_status)
    .execute(database)
    .await
    .expect("seed binding");
    id
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
    let env = setup("cltermux_exchange").await;
    let response = exchange_request(&env.router, None, valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn exchange_rejects_malformed_token_with_401() {
    let env = setup("cltermux_exchange").await;
    let response = exchange_request(&env.router, Some("not-a-jwt"), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn exchange_rejects_expired_token_with_401() {
    let env = setup("cltermux_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", "cltermux:access"],
        &["cltermux:access"],
    )
    .await;
    let token = issue_expired_token(&env.state, user_id, &client_id, &["cltermux:access"]);
    bind_row(&env.database, user_id, "cltermux:701", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn exchange_rejects_audience_outside_allowlist_with_401() {
    let env = setup("cltermux_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, _client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", "cltermux:access"],
        &["cltermux:access"],
    )
    .await;
    // allowlist 只含 ALLOWED_CLIENT_ID；签发一个 aud 为其他 client 的令牌。
    let outside = format!("outside-allowlist-{suffix}");
    let token = issue_token(&env.state, user_id, &outside, &["cltermux:access"]);
    bind_row(&env.database, user_id, "cltermux:702", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn exchange_rejects_revoked_token_with_401() {
    let env = setup("cltermux_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", "cltermux:access"],
        &["cltermux:access"],
    )
    .await;
    let token = issue_token(&env.state, user_id, &client_id, &["cltermux:access"]);
    env.state
        .revocations
        .revoke(&token, 3600)
        .await
        .expect("revoke token");
    bind_row(&env.database, user_id, "cltermux:703", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn exchange_rejects_missing_scope_with_403() {
    let env = setup("cltermux_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid"], &["openid"]).await;
    let token = issue_token(&env.state, user_id, &client_id, &["openid"]);
    bind_row(&env.database, user_id, "cltermux:704", "active").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "insufficient_scope");
}

#[tokio::test]
async fn exchange_without_binding_returns_account_not_linked() {
    let env = setup("cltermux_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", "cltermux:access"],
        &["cltermux:access"],
    )
    .await;
    let token = issue_token(&env.state, user_id, &client_id, &["cltermux:access"]);

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "account_not_linked");
}

#[tokio::test]
async fn exchange_with_disabled_binding_returns_account_disabled() {
    let env = setup("cltermux_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", "cltermux:access"],
        &["cltermux:access"],
    )
    .await;
    let token = issue_token(&env.state, user_id, &client_id, &["cltermux:access"]);
    bind_row(&env.database, user_id, "cltermux:705", "disabled").await;

    let response = exchange_request(&env.router, Some(&token), valid_device_body()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "account_disabled");
}

#[tokio::test]
async fn exchange_rejects_oversized_device_id_with_invalid_request() {
    let env = setup("cltermux_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", "cltermux:access"],
        &["cltermux:access"],
    )
    .await;
    let token = issue_token(&env.state, user_id, &client_id, &["cltermux:access"]);
    // 绑定存在，保证唯一被拒绝的原因是 device_id 超长（>255 字节）。
    bind_row(&env.database, user_id, "cltermux:706", "active").await;

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
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_request");
}

#[tokio::test]
async fn exchange_success_returns_session_token_with_binding_claims() {
    let env = setup("cltermux_exchange").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", "cltermux:access"],
        &["cltermux:access"],
    )
    .await;
    let token = issue_token(&env.state, user_id, &client_id, &["cltermux:access"]);
    let binding_id = bind_row(&env.database, user_id, "cltermux:777", "active").await;

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

    let body: Value = oauth_flow::json_body(response).await;
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
    assert_eq!(body["uid"], "cltermux:777");

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
        claims
            .scope
            .split_whitespace()
            .any(|scope| scope == "cltermux:access"),
        "session token must carry cltermux:access"
    );
    assert!(claims.exp >= claims.iat, "exp must not precede iat");
    assert!(
        claims.exp - claims.iat <= 300,
        "session token lifetime must be <= 300s"
    );

    // 绑定 claim 不在 `AccessTokenClaims` 里，从 payload 段读取。
    let payload = jwt_payload(session_token);
    assert_eq!(payload["uid"], "cltermux:777");
    assert_eq!(payload["binding_id"], binding_id);
    assert_eq!(payload["binding_version"], 1);
}
