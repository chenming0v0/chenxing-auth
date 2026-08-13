use axum::{
    Router,
    body::Body,
    extract::{Form, Query, State},
    http::{Request, StatusCode},
    response::Redirect,
    routing::get,
};
use chenxing_auth::{
    api, config::Config, sessions::cookies::EXTERNAL_STATE_COOKIE_PREFIX, state::AppState,
};
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

#[derive(Clone, Default)]
struct MockState {
    subject: String,
    token_form: Arc<Mutex<Option<HashMap<String, String>>>>,
    user_email: Arc<Mutex<String>>,
    /// userinfo 响应里 `email_verified` 的原样取值。用 `Value` 而不是 `bool`，
    /// 才能覆盖「claim 缺失」和「类型不是 bool」这两种真实的 IdP 行为。
    email_verified: Arc<Mutex<Value>>,
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

async fn mock_server() -> (SocketAddr, MockState) {
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

async fn setup(
    mock: SocketAddr,
) -> (
    axum::Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    String,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("oauth_provider_flow", &database_url).await;
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-provider-flow-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "provider-flow-admin".to_owned();
    config.cookie_secure = false;
    // Issue #343：本用例的 provider 端点是本机 mock 服务器（127.0.0.1 回环），
    // 必须显式开启开发期回环例外；生产边界由 oauth_provider_endpoint_policy.rs
    // 的「默认拒绝回环」用例单独覆盖。
    config.oauth_provider_loopback_enabled = true;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let router = api::router(
        AppState::new_with_pool(config, database.clone())
            .await
            .expect("state"),
    );
    let slug = format!("mock-{}", Uuid::new_v4().simple());
    let input = serde_json::json!({
        "name":"Mock Provider", "slug":slug,
        "authorization_endpoint":format!("http://{mock}/authorize"),
        "token_endpoint":format!("http://{mock}/token"),
        "userinfo_endpoint":format!("http://{mock}/userinfo"),
        "client_id":"mock-client", "client_secret":"mock-secret",
        "scopes":["openid","profile","email"], "subject_claim":"sub", "email_claim":"email",
        "name_claim":"name", "email_verified_claim":"email_verified", "client_auth_method":"request_body"
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
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/oauth/providers/{slug}/enable"))
                .header("authorization", "Bearer provider-flow-admin")
                .body(Body::empty())
                .expect("enable request"),
        )
        .await
        .expect("enable response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    oauth_flow::ensure_owner_bootstrapped(
        &router,
        &database,
        "oauth_provider_flow",
        "oauth_provider_flow",
    )
    .await;
    (router, database, key_directory, slug)
}

fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("location")
        .to_owned()
}

fn set_cookie(response: &axum::response::Response, name: &str) -> String {
    set_cookie_header(response, name)
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned()
}

/// 断言「没有签发某个 Cookie」时用它：`set_cookie_header` 缺失即 panic，
/// 无法表达「本来就不该有」这个预期。
fn set_cookie_header_optional(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            value.starts_with(name).then(|| value.to_owned())
        })
}

fn set_cookie_header(response: &axum::response::Response, name: &str) -> String {
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
async fn custom_provider_registers_reuses_identity_and_rejects_state_replay() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let external_email = mock_state.user_email.lock().await.clone();
    let (router, database, key_directory, slug) = setup(mock).await;
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
    let authorize_location = location(&response);
    let authorize_response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("mock client")
        .get(&authorize_location)
        .send()
        .await
        .expect("mock authorize");
    assert_eq!(authorize_response.status(), reqwest::StatusCode::SEE_OTHER);
    let callback_location = authorize_response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("mock callback location")
        .to_owned();
    let callback = url::Url::parse(&callback_location).expect("callback URL");
    let state = callback
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", &state_cookie)
                .body(Body::empty())
                .expect("callback request"),
        )
        .await
        .expect("callback response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        location(&response).contains("external=success"),
        "unexpected callback location: {}",
        location(&response)
    );
    let first_session = set_cookie(&response, "chenxing_session=");
    let count: (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE subject = $1",
    )
    .bind(&external_subject)
    .fetch_one(&database)
    .await
    .expect("identity count");
    assert_eq!(count.0, 1);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}"))
                .body(Body::empty())
                .expect("second start"),
        )
        .await
        .expect("second start response");
    let second_state_cookie = set_cookie(&response, EXTERNAL_STATE_COOKIE_PREFIX);
    let second_location = location(&response);
    let second_authorize = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("mock client")
        .get(&second_location)
        .send()
        .await
        .expect("second authorize");
    let second_callback = second_authorize
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("second callback location")
        .to_owned();
    let second_state = url::Url::parse(&second_callback)
        .expect("second callback URL")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("second state");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={second_state}"
                ))
                .header("cookie", &second_state_cookie)
                .body(Body::empty())
                .expect("second callback request"),
        )
        .await
        .expect("second callback response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(set_cookie(&response, "chenxing_session=") != first_session);
    let count: (i64,) =
        chenxing_auth::sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind(&external_email)
            .fetch_one(&database)
            .await
            .expect("user count");
    assert_eq!(count.0, 1);
    let password_login_enabled: (bool,) =
        chenxing_auth::sqlx::query_as("SELECT password_login_enabled FROM users WHERE email = $1")
            .bind(&external_email)
            .fetch_one(&database)
            .await
            .expect("external user password login flag");
    assert!(!password_login_enabled.0);

    let token_form = mock_state
        .token_form
        .lock()
        .await
        .clone()
        .expect("token form");
    // RFC 7636 §4.5：token 请求必须带上 code_verifier，把授权码绑定到本次授权会话。
    // verifier 是随机值，先取出后单独校验，再比对其余字段的精确集合。
    let code_verifier = token_form
        .get("code_verifier")
        .expect("token 请求必须包含 code_verifier")
        .clone();
    assert!(
        (43..=128).contains(&code_verifier.len()),
        "code_verifier 长度必须符合 RFC 7636 §4.1: {}",
        code_verifier.len()
    );
    assert!(
        code_verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)),
        "code_verifier 必须只含 RFC 7636 unreserved 字符: {code_verifier}"
    );
    // 授权请求里发出的 challenge 必须等于 S256(verifier)。
    let sent_challenge = authorization_query(&second_location, "code_challenge")
        .expect("授权请求必须包含 code_challenge");
    assert_eq!(
        authorization_query(&second_location, "code_challenge_method").as_deref(),
        Some("S256"),
        "code_challenge_method 必须是 S256"
    );
    assert_eq!(
        sent_challenge,
        s256_challenge(&code_verifier),
        "code_challenge 必须等于 BASE64URL(SHA256(code_verifier))"
    );
    let expected_form = HashMap::from([
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), "mock-code".to_owned()),
        (
            "redirect_uri".to_owned(),
            format!("http://127.0.0.1:3000/auth/external/{slug}/callback"),
        ),
        ("client_id".to_owned(), "mock-client".to_owned()),
        ("client_secret".to_owned(), "mock-secret".to_owned()),
        ("code_verifier".to_owned(), code_verifier),
    ]);
    assert_eq!(token_form, expected_form);

    let replay = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={second_state}"
                ))
                .header("cookie", &second_state_cookie)
                .body(Body::empty())
                .expect("replay request"),
        )
        .await
        .expect("replay response");
    assert_eq!(replay.status(), StatusCode::SEE_OTHER);
    assert!(location(&replay).contains("external_error=oauth_login_failed"));
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn custom_provider_does_not_auto_link_existing_email() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let external_email = mock_state.user_email.lock().await.clone();
    let (router, database, key_directory, slug) = setup(mock).await;
    let registration = serde_json::json!({
        "username": format!("local-{}", Uuid::new_v4().simple()),
        "email": external_email,
        "password": "local-password-123",
        "display_name": "Local Person"
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(registration.to_string()))
                .expect("registration request"),
        )
        .await
        .expect("registration response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        oauth_flow::json_body(response).await["code"],
        "email_verification_unavailable"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", "Bearer provider-flow-admin")
                .header("content-type", "application/json")
                .body(Body::from(registration.to_string()))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);

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
    let state_cookie = set_cookie(&response, EXTERNAL_STATE_COOKIE_PREFIX);
    let authorize_response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("mock client")
        .get(location(&response))
        .send()
        .await
        .expect("mock authorize");
    let callback_location = authorize_response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("callback location");
    let state = url::Url::parse(callback_location)
        .expect("callback URL")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state");
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", state_cookie)
                .body(Body::empty())
                .expect("callback request"),
        )
        .await
        .expect("callback response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(location(&response).contains("external_error=oauth_account_link_required"));

    let identities: (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_external_identities WHERE subject = $1",
    )
    .bind(&external_subject)
    .fetch_one(&database)
    .await
    .expect("identity count");
    assert_eq!(identities.0, 0);
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 跑完一整轮外部登录：发起 → 外部 IdP 授权 → 回调。返回回调响应。
async fn run_external_login(router: &axum::Router, slug: &str) -> axum::response::Response {
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
        .build()
        .expect("mock client")
        .get(location(&response))
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
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", state_cookie)
                .body(Body::empty())
                .expect("callback request"),
        )
        .await
        .expect("callback response")
}

/// Issue #261：未验证邮箱既不能登录，也不能自动建号。
///
/// 覆盖三种真实的 IdP 行为：完全不返回 claim、返回 false、返回非 bool 值。
/// 过去只有第二种会被拦下，第一种直接放行建号，第三种取决于路径细节。
#[tokio::test]
async fn custom_provider_rejects_unverified_external_email() {
    let (mock, mock_state) = mock_server().await;
    let external_subject = mock_state.subject.clone();
    let external_email = mock_state.user_email.lock().await.clone();
    let (router, database, key_directory, slug) = setup(mock).await;

    for claim in [
        serde_json::Value::Null,
        serde_json::json!(false),
        serde_json::json!("true"),
        serde_json::json!(1),
    ] {
        *mock_state.email_verified.lock().await = claim.clone();
        let response = run_external_login(&router, &slug).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let redirect = location(&response);
        assert!(
            redirect.contains("external_error=oauth_email_unverified"),
            "email_verified={claim} 必须被拒绝，实际跳转: {redirect}"
        );
        assert!(
            set_cookie_header_optional(&response, "chenxing_session=").is_none(),
            "被拒绝的外部登录不得签发会话 Cookie"
        );

        let identities: (i64,) = chenxing_auth::sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_external_identities WHERE subject = $1",
        )
        .bind(&external_subject)
        .fetch_one(&database)
        .await
        .expect("identity count");
        assert_eq!(identities.0, 0, "email_verified={claim} 不得建立外部身份");
        let users: (i64,) =
            chenxing_auth::sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = $1")
                .bind(&external_email)
                .fetch_one(&database)
                .await
                .expect("user count");
        assert_eq!(users.0, 0, "email_verified={claim} 不得自动建号");
    }

    // 同一个 provider 在 claim 变成 true 之后必须能正常登录，
    // 证明拒绝来自 claim 取值而不是配置被误伤。
    *mock_state.email_verified.lock().await = serde_json::json!(true);
    let response = run_external_login(&router, &slug).await;
    assert!(location(&response).contains("external=success"));
    let users: (i64,) =
        chenxing_auth::sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind(&external_email)
            .fetch_one(&database)
            .await
            .expect("user count");
    assert_eq!(users.0, 1);
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 存量行的 email_verified_claim 可能是 NULL。这类 provider 不能被启用，
/// 已经启用的（迁移前写入的）也不能放行外部登录。
#[tokio::test]
async fn legacy_provider_without_email_verified_claim_cannot_enable_or_login() {
    let (mock, _mock_state) = mock_server().await;
    let (router, database, key_directory, slug) = setup(mock).await;

    // 绕过应用层写出一个存量形态的行：claim 为 NULL 且处于启用状态。
    // CHECK 约束禁止 active + NULL 的组合，所以先停用再清空 claim，
    // 最后直接改 status，模拟迁移前留下的数据。
    chenxing_auth::sqlx::query(
        "UPDATE oauth_providers SET status = 'disabled', email_verified_claim = NULL WHERE slug = $1",
    )
    .bind(&slug)
    .execute(&database)
    .await
    .expect("clear email_verified_claim");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/oauth/providers/{slug}/enable"))
                .header("authorization", "Bearer provider-flow-admin")
                .body(Body::empty())
                .expect("enable request"),
        )
        .await
        .expect("enable response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let status: (String,) =
        chenxing_auth::sqlx::query_as("SELECT status FROM oauth_providers WHERE slug = $1")
            .bind(&slug)
            .fetch_one(&database)
            .await
            .expect("provider status");
    assert_eq!(status.0, "disabled", "启用必须被拒绝且不改动存储状态");

    // 迁移前写入的 active + NULL 行：登录入口必须直接拒绝。
    chenxing_auth::sqlx::query(
        "ALTER TABLE oauth_providers DROP CONSTRAINT oauth_providers_active_requires_email_verified_claim",
    )
    .execute(&database)
    .await
    .expect("drop constraint for legacy row simulation");
    chenxing_auth::sqlx::query("UPDATE oauth_providers SET status = 'active' WHERE slug = $1")
        .bind(&slug)
        .execute(&database)
        .await
        .expect("force legacy active row");

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
    let redirect = location(&response);
    assert!(
        redirect.contains("external_error=oauth_provider_not_found"),
        "缺少 claim 的 provider 不得跳转外部 IdP，实际: {redirect}"
    );
    assert!(
        !redirect.starts_with("http"),
        "不得把用户送到外部 IdP: {redirect}"
    );
    let _ = std::fs::remove_dir_all(key_directory);
}
