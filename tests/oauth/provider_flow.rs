use axum::{
    Router,
    body::Body,
    extract::{Form, Query, State},
    http::{Request, StatusCode},
    response::Redirect,
    routing::get,
};
use chenxing_auth::sessions::cookies::EXTERNAL_STATE_COOKIE_PREFIX;
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt;
use uuid::Uuid;

use crate::http;
use crate::oauth_flow;

mod custom_provider;

#[derive(Clone, Default)]
pub(super) struct MockState {
    pub(super) subject: String,
    pub(super) token_form: Arc<Mutex<Option<HashMap<String, String>>>>,
    pub(super) user_email: Arc<Mutex<String>>,
    /// userinfo 响应里 `email_verified` 的原样取值。用 `Value` 而不是 `bool`，
    /// 才能覆盖「claim 缺失」和「类型不是 bool」这两种真实的 IdP 行为。
    pub(super) email_verified: Arc<Mutex<Value>>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    redirect_uri: String,
    state: String,
}

async fn mock_authorize(Query(query): Query<AuthorizeQuery>) -> Redirect {
    Redirect::to(&format!(
        "{}?code=mock-code&state={}",
        query.redirect_uri, query.state
    ))
}

async fn mock_token(
    State(state): State<MockState>,
    Form(form): Form<HashMap<String, String>>,
) -> axum::Json<Value> {
    *state.token_form.lock().await = Some(form);
    axum::Json(serde_json::json!({"access_token":"mock-access-token","token_type":"Bearer"}))
}

async fn mock_userinfo(State(state): State<MockState>) -> axum::Json<Value> {
    let email = state.user_email.lock().await.clone();
    let mut claims = serde_json::json!({
        "sub": state.subject,
        "email": email,
        "name": "External Person"
    });
    // Value::Null 表示 IdP 完全不返回该 claim，而不是返回一个 null 值。
    let email_verified = state.email_verified.lock().await.clone();
    if !email_verified.is_null() {
        claims["email_verified"] = email_verified;
    }
    axum::Json(claims)
}

pub(super) async fn mock_server() -> (SocketAddr, MockState) {
    let email = format!("external-{}@example.com", Uuid::new_v4().simple());
    let state = MockState {
        subject: format!("mock-subject-{}", Uuid::new_v4().simple()),
        user_email: Arc::new(Mutex::new(email)),
        email_verified: Arc::new(Mutex::new(serde_json::json!(true))),
        ..MockState::default()
    };
    let router = Router::new()
        .route("/authorize", get(mock_authorize))
        .route("/token", axum::routing::post(mock_token))
        .route("/userinfo", get(mock_userinfo))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener");
    let address = listener.local_addr().expect("mock address");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("mock server");
    });
    (address, state)
}

pub(super) async fn setup(
    mock: SocketAddr,
) -> (
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    String,
) {
    let harness = crate::harness::HarnessBuilder::new("oauth_provider_flow")
        .admin_token("provider-flow-admin")
        // Issue #343：本用例的 provider 端点是本机 mock 服务器（127.0.0.1 回环），
        // 必须显式开启开发期回环例外；生产边界由 oauth_provider_endpoint_policy.rs
        // 的「默认拒绝回环」用例单独覆盖。
        .configure(|config| config.oauth_provider_loopback_enabled = true)
        .build()
        .await;
    let router = harness.router;
    let slug = format!("mock-{}", Uuid::new_v4().simple());
    create_enabled_provider(&router, mock, &slug).await;
    oauth_flow::ensure_owner_bootstrapped(
        &router,
        &harness.database,
        "oauth_provider_flow",
        "oauth_provider_flow",
    )
    .await;
    (router, harness.database, harness.key_directory, slug)
}

async fn create_enabled_provider(router: &axum::Router, mock: SocketAddr, slug: &str) {
    let input = serde_json::json!({
        "name": format!("Mock Provider {slug}"),
        "slug": slug,
        "authorization_endpoint": format!("http://{mock}/authorize"),
        "token_endpoint": format!("http://{mock}/token"),
        "userinfo_endpoint": format!("http://{mock}/userinfo"),
        "client_id": "mock-client",
        "client_secret": "mock-secret",
        "scopes": ["openid", "profile", "email"],
        "subject_claim": "sub",
        "email_claim": "email",
        "name_claim": "name",
        "email_verified_claim": "email_verified",
        "client_auth_method": "request_body"
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/oauth/providers")
                .header("authorization", "Bearer provider-flow-admin")
                .header("content-type", "application/json")
                .body(Body::from(input.to_string()))
                .expect("provider request"),
        )
        .await
        .expect("provider response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = http::json_body(response).await;
    let state_version = created["state_version"]
        .as_i64()
        .expect("created provider state_version");

    enable_provider(router, "provider-flow-admin", slug, state_version).await;
}

async fn enable_provider(router: &axum::Router, token: &str, slug: &str, expected_version: i64) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/oauth/providers/{slug}/enable"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "expected_version": expected_version }).to_string(),
                ))
                .expect("enable request"),
        )
        .await
        .expect("enable response");
    assert_eq!(response.status(), StatusCode::OK);
}

pub(super) fn set_cookie(response: &axum::response::Response, name: &str) -> String {
    set_cookie_header(response, name)
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned()
}

/// 断言「没有签发某个 Cookie」时用它：`set_cookie_header` 缺失即 panic，
/// 无法表达「本来就不该有」这个预期。
pub(super) fn set_cookie_header_optional(
    response: &axum::response::Response,
    name: &str,
) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            value.starts_with(name).then(|| value.to_owned())
        })
}

pub(super) fn set_cookie_header(response: &axum::response::Response, name: &str) -> String {
    set_cookie_header_optional(response, name).expect("cookie")
}

/// 从发往外部 IdP 的授权 URL 中取出指定 query 参数。
fn authorization_query(location: &str, key: &str) -> Option<String> {
    url::Url::parse(location)
        .expect("authorization URL")
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

/// RFC 7636 §4.2: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
fn s256_challenge(verifier: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[tokio::test]
async fn transplanted_provider_ciphertext_is_rejected_before_token_request() {
    let (mock, mock_state) = mock_server().await;
    let (router, database, key_directory, source_slug) = setup(mock).await;
    let target_slug = format!("transplant-{}", Uuid::new_v4().simple());
    let input = serde_json::json!({
        "name": "Transplant Target",
        "slug": target_slug,
        "authorization_endpoint": format!("http://{mock}/authorize"),
        "token_endpoint": format!("http://{mock}/token"),
        "userinfo_endpoint": format!("http://{mock}/userinfo"),
        "client_id": "target-client",
        "client_secret": "target-secret",
        "scopes": ["openid", "email"],
        "subject_claim": "sub",
        "email_claim": "email",
        "name_claim": "name",
        "email_verified_claim": "email_verified",
        "client_auth_method": "request_body"
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/oauth/providers")
                .header("authorization", "Bearer provider-flow-admin")
                .header("content-type", "application/json")
                .body(Body::from(input.to_string()))
                .expect("target provider request"),
        )
        .await
        .expect("target provider response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = http::json_body(response).await;
    let state_version = created["state_version"]
        .as_i64()
        .expect("target provider state_version");
    enable_provider(&router, "provider-flow-admin", &target_slug, state_version).await;

    chenxing_auth::sqlx::query(
        "UPDATE oauth_providers AS target
         SET client_secret_ciphertext = source.client_secret_ciphertext
         FROM oauth_providers AS source
         WHERE target.slug = $1 AND source.slug = $2",
    )
    .bind(&target_slug)
    .bind(&source_slug)
    .execute(&database)
    .await
    .expect("transplant provider ciphertext");

    let start = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{target_slug}"))
                .body(Body::empty())
                .expect("start transplanted provider"),
        )
        .await
        .expect("start response");
    assert_eq!(start.status(), StatusCode::SEE_OTHER);
    let state_cookie = set_cookie(&start, EXTERNAL_STATE_COOKIE_PREFIX);
    let state = authorization_query(&http::location(&start), "state").expect("authorization state");
    let callback = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{target_slug}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", state_cookie)
                .body(Body::empty())
                .expect("transplanted provider callback"),
        )
        .await
        .expect("callback response");

    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert!(
        http::location(&callback).contains("external_error=oauth_login_failed"),
        "transplanted ciphertext must use the unified external OAuth failure redirect: {}",
        http::location(&callback)
    );
    assert!(
        mock_state.token_form.lock().await.is_none(),
        "a transplanted ciphertext must fail before any secret reaches the target endpoint"
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn callback_provider_slug_mismatch_preserves_login_state_and_cookie() {
    let (mock, _mock_state) = mock_server().await;
    let (router, _database, key_directory, provider_a) = setup(mock).await;
    let provider_b = format!("mock-{}", Uuid::new_v4().simple());
    create_enabled_provider(&router, mock, &provider_b).await;

    let start = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{provider_a}"))
                .body(Body::empty())
                .expect("provider A login start request"),
        )
        .await
        .expect("provider A login start response");
    assert_eq!(start.status(), StatusCode::SEE_OTHER);
    let state_cookie = set_cookie(&start, EXTERNAL_STATE_COOKIE_PREFIX);
    let state_cookie_name = state_cookie
        .split_once('=')
        .map(|(name, _)| name)
        .expect("state cookie name");
    let state = authorization_query(&http::location(&start), "state").expect("authorization state");

    let wrong_provider = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{provider_b}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", &state_cookie)
                .body(Body::empty())
                .expect("provider B callback request"),
        )
        .await
        .expect("provider B callback response");
    assert_eq!(wrong_provider.status(), StatusCode::SEE_OTHER);
    assert!(
        http::location(&wrong_provider).contains("external_error=oauth_login_failed"),
        "a provider mismatch must retain the existing external login failure response"
    );
    assert!(
        set_cookie_header_optional(&wrong_provider, &format!("{state_cookie_name}=")).is_none(),
        "a provider mismatch must not clear provider A's valid state cookie"
    );

    let correct_provider = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{provider_a}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", &state_cookie)
                .body(Body::empty())
                .expect("provider A callback request"),
        )
        .await
        .expect("provider A callback response");
    assert_eq!(correct_provider.status(), StatusCode::SEE_OTHER);
    assert!(
        http::location(&correct_provider).contains("external=success"),
        "the original provider must still be able to consume its state: {}",
        http::location(&correct_provider)
    );
    assert!(
        set_cookie_header(&correct_provider, &format!("{state_cookie_name}="))
            .contains("Max-Age=0"),
        "a state consumed by the correct provider must still clear its state cookie"
    );

    let error_start = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{provider_a}"))
                .body(Body::empty())
                .expect("provider A error-path login start request"),
        )
        .await
        .expect("provider A error-path login start response");
    let error_state_cookie = set_cookie(&error_start, EXTERNAL_STATE_COOKIE_PREFIX);
    let error_state_cookie_name = error_state_cookie
        .split_once('=')
        .map(|(name, _)| name)
        .expect("error-path state cookie name");
    let error_state = authorization_query(&http::location(&error_start), "state")
        .expect("error-path authorization state");
    let consumed_error = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{provider_a}/callback?error=access_denied&state={error_state}"
                ))
                .header("cookie", &error_state_cookie)
                .body(Body::empty())
                .expect("provider A error callback request"),
        )
        .await
        .expect("provider A error callback response");
    assert_eq!(consumed_error.status(), StatusCode::SEE_OTHER);
    assert!(http::location(&consumed_error).contains("external_error=oauth_login_failed"));
    assert!(
        set_cookie_header(&consumed_error, &format!("{error_state_cookie_name}="))
            .contains("Max-Age=0"),
        "a state consumed before a provider error must still clear its state cookie"
    );

    let _ = std::fs::remove_dir_all(key_directory);
}

/// 跑完一整轮外部登录：发起 → 外部 IdP 授权 → 回调。返回回调响应。
pub(super) async fn run_external_login(
    router: &axum::Router,
    slug: &str,
) -> axum::response::Response {
    run_external_login_with_cookies(router, slug, None).await
}

pub(super) async fn run_external_login_with_cookies(
    router: &axum::Router,
    slug: &str,
    extra_cookies: Option<&str>,
) -> axum::response::Response {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("start request"),
        )
        .await
        .expect("start response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let state_cookie = set_cookie(&response, EXTERNAL_STATE_COOKIE_PREFIX);
    let authorize_response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("mock client")
        .get(http::location(&response))
        .send()
        .await
        .expect("mock authorize");
    let callback_location = authorize_response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("callback location")
        .to_owned();
    let state = url::Url::parse(&callback_location)
        .expect("callback URL")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state");
    let cookie = match extra_cookies {
        Some(extra) => format!("{state_cookie}; {extra}"),
        None => state_cookie,
    };
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("callback request"),
        )
        .await
        .expect("callback response")
}
