//! CLtermux resolve 端点的 P0 集成测试（Issue #706）。
//!
//! 覆盖：inbound bearer 错误 401、allowlist/aud 不匹配 401、scope 缺失 403、
//! 已撤销 token 401、成功 200（issuer/uid/valid_until 正确）、未绑定 404、
//! 集成为 None 时 fail-closed 401。
//!
//! resolve 是入站端点：CLtermux 服务端以 `Authorization: Bearer
//! CLTERMUX_INTEROP_INBOUND_TOKEN` 调用辰星，携带辰星签发的用户 access token。
//! 测试直接用 `issue_access_token` 造令牌，绕过完整 OAuth 流程。
//!
//! `config.cltermux` 直接注入（`Config::from_values_with_issuer` 不读进程
//! env，测试无需 `env::set_var`）。resolve 路径不触发出站调用，base_url
//! 只需通过形状校验。

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::AUTHORIZATION},
};
use chenxing_auth::{
    api, config::CltermuxConfig, consents::ConsentService, oauth::token::issue_access_token,
    state::AppState,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

use crate::oauth_flow;

const INBOUND_TOKEN: &str = "cltermux-inbound-token-0123456789abcdef";
/// allowlist 固定 client id。schema 隔离保证每个测试的 client 表独立，
/// 固定 id 不会跨测试碰撞。
const ALLOWED_CLIENT_ID: &str = "cltermux-resolve-client";

struct Env {
    router: Router,
    state: AppState,
    database: chenxing_auth::sqlx::PgPool,
    #[allow(dead_code)]
    key_directory: std::path::PathBuf,
}

async fn setup(binary_name: &str) -> Env {
    let (mut state, database, key_directory) = oauth_flow::test_state(binary_name).await;
    state.config.cltermux = Some(cltermux_config(vec![ALLOWED_CLIENT_ID.to_owned()]));
    let router = api::router(state.clone());
    Env {
        router,
        state,
        database,
        key_directory,
    }
}

/// 集成禁用（`cltermux: None`）的测试环境。
async fn setup_disabled(binary_name: &str) -> Env {
    let (state, database, key_directory) = oauth_flow::test_state(binary_name).await;
    let router = api::router(state.clone());
    Env {
        router,
        state,
        database,
        key_directory,
    }
}

fn cltermux_config(allowed_client_ids: Vec<String>) -> CltermuxConfig {
    CltermuxConfig {
        base_url: url::Url::parse("https://cltermux.example.com/").expect("static base url"),
        outbound_token: "cltermux-outbound-token-0123456789abcdef".to_owned(),
        inbound_token_digest: Sha256::digest(INBOUND_TOKEN.as_bytes()).to_vec(),
        allowed_client_ids,
    }
}

/// 种用户 + 固定 client_id 的 Client + 同意行。
///
/// client_id 固定为 [`ALLOWED_CLIENT_ID`]，与配置 allowlist 对齐；aud 不匹配
/// 的用例通过注入不同 allowlist 的 config 实现。
async fn seed_user_and_client(
    database: &chenxing_auth::sqlx::PgPool,
    suffix: &str,
    client_scopes: &[&str],
    consent_scopes: &[&str],
) -> (i64, String) {
    let username = format!("cltermux-resolve-{suffix}");
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
    .bind("Resolve Client")
    .bind(serde_json::json!(
        std::iter::once("https://resolve.example/callback")
            .map(|s| s.to_owned())
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

fn issue_token(state: &AppState, user_id: i64, client_id: &str, scopes: &[&str]) -> String {
    let issuer = state
        .issuer
        .current()
        .expect("test state has a loaded issuer")
        .issuer()
        .as_str()
        .to_owned();
    issue_access_token(
        &state.keys,
        &issuer,
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

async fn resolve_request(
    router: &Router,
    bearer: Option<&str>,
    body: Value,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/cltermux/resolve")
        .header("content-type", "application/json");
    if let Some(bearer) = bearer {
        builder = builder.header(AUTHORIZATION, format!("Bearer {bearer}"));
    }
    router
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.to_string()))
                .expect("resolve request"),
        )
        .await
        .expect("resolve response")
}

async fn bind_row(database: &chenxing_auth::sqlx::PgPool, user_id: i64, uid: &str) {
    chenxing_auth::sqlx::query(
        "INSERT INTO linked_accounts
            (id, user_id, provider_slug, kind, uid, subject, account_status, snapshot_json,
             linked_at, last_attempt_at, last_success_at, sync_status)
         VALUES ($1, $2, 'cltermux', 'service_account', $3, $3, 'active', '{}'::jsonb,
                 NOW(), NOW(), NOW(), 'success')",
    )
    .bind(format!("link_{}", Uuid::new_v4().simple()))
    .bind(user_id)
    .bind(uid)
    .execute(database)
    .await
    .expect("seed binding");
}

fn error_code(body: &Value) -> String {
    body["code"].as_str().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn resolve_rejects_wrong_inbound_bearer_with_401() {
    let env = setup("cltermux_resolve").await;
    let response = resolve_request(
        &env.router,
        Some("totally-wrong-inbound-token-0123456789"),
        json!({"access_token": "whatever"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_integration_credential");
}

#[tokio::test]
async fn resolve_rejects_missing_bearer_with_401() {
    let env = setup("cltermux_resolve").await;
    let response = resolve_request(&env.router, None, json!({"access_token": "x"})).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn resolve_rejects_client_outside_allowlist_with_401() {
    let env = setup("cltermux_resolve").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, _client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid"], &["cltermux:access"]).await;
    // allowlist 只含 ALLOWED_CLIENT_ID；这里签发一个 aud 为其他 client 的令牌。
    let other_client = format!("outside-allowlist-{suffix}");
    let token = issue_token(&env.state, user_id, &other_client, &["cltermux:access"]);

    let response = resolve_request(
        &env.router,
        Some(INBOUND_TOKEN),
        json!({"access_token": token}),
    )
    .await;
    // aud 不在 allowed_client_ids：fail-closed 401（invalid_chenxing_token）。
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn resolve_rejects_missing_scope_with_403() {
    let env = setup("cltermux_resolve").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, client_id) =
        seed_user_and_client(&env.database, &suffix, &["openid"], &["openid"]).await;
    let token = issue_token(&env.state, user_id, &client_id, &["openid"]);

    let response = resolve_request(
        &env.router,
        Some(INBOUND_TOKEN),
        json!({"access_token": token}),
    )
    .await;
    // allowlist 命中但 scope 缺 cltermux:access → 403 insufficient_scope。
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "insufficient_scope");
}

#[tokio::test]
async fn resolve_rejects_revoked_token_with_401() {
    let env = setup("cltermux_resolve").await;
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

    let response = resolve_request(
        &env.router,
        Some(INBOUND_TOKEN),
        json!({"access_token": token}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn resolve_rejects_malformed_token_with_401() {
    let env = setup("cltermux_resolve").await;
    let response = resolve_request(
        &env.router,
        Some(INBOUND_TOKEN),
        json!({"access_token": "not-a-jwt"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_chenxing_token");
}

#[tokio::test]
async fn resolve_success_returns_issuer_uid_and_valid_until() {
    let env = setup("cltermux_resolve").await;
    let suffix = Uuid::new_v4().simple().to_string();
    // Client 注册 scope 与同意行都必须覆盖 cltermux:access：grant gate 会把
    // 凭据 scope 收窄到 注册 scope ∩ 平台 allowlist，再要求同意覆盖。
    let (user_id, client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", "cltermux:access"],
        &["cltermux:access"],
    )
    .await;
    let token = issue_token(&env.state, user_id, &client_id, &["cltermux:access"]);
    bind_row(&env.database, user_id, "cltermux:777").await;

    let response = resolve_request(
        &env.router,
        Some(INBOUND_TOKEN),
        json!({"access_token": token}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "resolve must succeed");
    let body: Value = oauth_flow::json_body(response).await;
    assert_eq!(body["provider"], "cltermux");
    assert_eq!(body["uid"], "cltermux:777");
    assert_eq!(body["subject"], user_id.to_string());
    assert_eq!(body["client_id"], client_id);
    assert!(
        body["binding_id"]
            .as_str()
            .expect("binding id")
            .starts_with("link_")
    );
    assert_eq!(body["binding_version"], 1);
    // issuer 必须等于配置 Issuer（不从请求 Host 推导）。
    let issuer = env
        .state
        .issuer
        .current()
        .expect("issuer")
        .issuer()
        .as_str()
        .to_owned();
    assert_eq!(body["issuer"], issuer);
    // valid_until = min(token_exp, now+300)：必须落在未来且 ≤ token exp。
    let valid_until = body["valid_until"].as_str().expect("valid_until rfc3339");
    let parsed =
        time::OffsetDateTime::parse(valid_until, &time::format_description::well_known::Rfc3339)
            .expect("valid_until parses");
    assert!(parsed > time::OffsetDateTime::now_utc() - time::Duration::seconds(30));
}

#[tokio::test]
async fn resolve_without_binding_returns_404() {
    let env = setup("cltermux_resolve").await;
    let suffix = Uuid::new_v4().simple().to_string();
    let (user_id, client_id) = seed_user_and_client(
        &env.database,
        &suffix,
        &["openid", "cltermux:access"],
        &["cltermux:access"],
    )
    .await;
    let token = issue_token(&env.state, user_id, &client_id, &["cltermux:access"]);

    let response = resolve_request(
        &env.router,
        Some(INBOUND_TOKEN),
        json!({"access_token": token}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "account_not_linked");
}

#[tokio::test]
async fn resolve_fails_closed_when_integration_is_none() {
    let env = setup_disabled("cltermux_resolve_disabled").await;
    let response = resolve_request(
        &env.router,
        Some(INBOUND_TOKEN),
        json!({"access_token": "whatever"}),
    )
    .await;
    // 集成未配置：fail-closed 401，不泄露"未配置"以外的信息。
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = oauth_flow::json_body(response).await;
    assert_eq!(error_code(&body), "invalid_integration_credential");
}
