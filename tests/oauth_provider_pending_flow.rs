use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Redirect,
    routing::get,
};
use chenxing_auth::{api, config::Config, state::AppState};
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
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
    user_email: Arc<Mutex<String>>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    redirect_uri: String,
    state: String,
}

async fn mock_authorize(
    axum::extract::Query(query): axum::extract::Query<AuthorizeQuery>,
) -> Redirect {
    Redirect::to(&format!(
        "{}?code=mock-code&state={}",
        query.redirect_uri, query.state
    ))
}

async fn mock_token() -> axum::Json<Value> {
    axum::Json(serde_json::json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer"
    }))
}

async fn mock_userinfo(
    axum::extract::State(state): axum::extract::State<MockState>,
) -> axum::Json<Value> {
    let email = state.user_email.lock().await.clone();
    axum::Json(serde_json::json!({
        "sub": state.subject,
        "email": email,
        "name": "External Person",
        "email_verified": true
    }))
}

async fn mock_server() -> SocketAddr {
    let state = MockState {
        subject: format!("mock-subject-{}", Uuid::new_v4().simple()),
        user_email: Arc::new(Mutex::new(format!(
            "external-{}@example.com",
            Uuid::new_v4().simple()
        ))),
    };
    let router = Router::new()
        .route("/authorize", get(mock_authorize))
        .route("/token", axum::routing::post(mock_token))
        .route("/userinfo", get(mock_userinfo))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener");
    let address = listener.local_addr().expect("mock address");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("mock server");
    });
    address
}

async fn setup(
    mock: SocketAddr,
) -> (
    Router,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
    String,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("oauth_provider_pending_flow", &database_url).await;
    let key_directory =
        std::env::temp_dir().join(format!("chenxing-provider-pending-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = "provider-pending-admin".to_owned();
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
    let slug = format!("mock-pending-{}", Uuid::new_v4().simple());
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
                .header("authorization", "Bearer provider-pending-admin")
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
                .header("authorization", "Bearer provider-pending-admin")
                .body(Body::empty())
                .expect("enable request"),
        )
        .await
        .expect("enable response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    oauth_flow::ensure_owner_bootstrapped(
        &router,
        &database,
        "oauth_provider_pending_flow",
        "oauth_provider_pending_flow",
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
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            let pair = value.split(';').next()?.to_owned();
            pair.starts_with(name).then_some(pair)
        })
        .expect("cookie")
}

async fn create_pending_request(router: &Router) -> (String, String, String) {
    let client_name = format!("Pending External Client {}", Uuid::new_v4().simple());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", "Bearer provider-pending-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": client_name,
                        "redirect_uris": ["https://pending.example/callback"],
                        "scopes": ["openid", "profile"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("client body");
    let client: Value = serde_json::from_slice(&body).expect("client JSON");
    let client_id = client["client_id"].as_str().expect("client id");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fpending.example%2Fcallback&response_type=code&scope=openid%20profile&state=pending-state&nonce=pending-nonce&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
                ))
                .header("accept", "text/html")
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    // `/oauth/authorize` 在这里签发 authorization holder cookie（src/oauth/handlers.rs:149）。
    // Issue #135 之后，认领 pending 请求必须出示它，所以测试要一路带到外部回调。
    let holder_cookie = set_cookie(&response, "chenxing_authz_holder");
    let login_location = location(&response);
    let request_id = url::Url::parse(&format!("http://localhost{login_location}"))
        .expect("login URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request id");
    (request_id, client_id.to_owned(), holder_cookie)
}

async fn begin_external_login(router: &Router, slug: &str, request_id: &str) -> (String, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/external/{slug}?request_id={request_id}"))
                .body(Body::empty())
                .expect("start request"),
        )
        .await
        .expect("start response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let state_cookie = set_cookie(&response, "chenxing_external_oauth_state_");
    let authorize_response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("mock client")
        .get(location(&response))
        .send()
        .await
        .expect("mock authorize");
    assert_eq!(authorize_response.status(), reqwest::StatusCode::SEE_OTHER);
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
    (state_cookie, state)
}

async fn complete_external_callback(
    router: &Router,
    slug: &str,
    state_cookie: &str,
    state: &str,
    holder_cookie: &str,
) -> axum::response::Response {
    callback_with_cookies(
        router,
        slug,
        state,
        // 外部 IdP 回调是顶层导航，SameSite=Lax 的 holder cookie 会随请求发送。
        &format!("{state_cookie}; {holder_cookie}"),
    )
    .await
}

async fn callback_with_cookies(
    router: &Router,
    slug: &str,
    state: &str,
    cookies: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/external/{slug}/callback?code=mock-code&state={state}"
                ))
                .header("cookie", cookies)
                .body(Body::empty())
                .expect("callback request"),
        )
        .await
        .expect("callback response")
}

fn set_cookies(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

/// 断言绑定失败的响应没有下发可用的登录凭据：会话与 CSRF Cookie 只能是清理指令
/// （空值 + Max-Age=0），不能带真实令牌（#266）。
fn assert_login_cookies_cleared(response: &axum::response::Response) {
    let cookies = set_cookies(response);
    for name in ["chenxing_session", "chenxing_csrf"] {
        let cookie = cookies
            .iter()
            .find(|value| value.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing clear directive for {name}"));
        assert!(
            cookie.starts_with(&format!("{name}=;")),
            "{name} must be cleared, got: {cookie}"
        );
        assert!(
            cookie.contains("Max-Age=0"),
            "{name} must expire immediately, got: {cookie}"
        );
    }
}

/// 外部身份在 `resolve_user` 阶段就已落库，因此可以按 provider slug 反查本地用户，
/// 不需要把 mock 里的随机邮箱透出来。
async fn external_user_id(database: &chenxing_auth::sqlx::PgPool, slug: &str) -> i64 {
    let (user_id,): (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT identity.user_id FROM oauth_external_identities identity \
         JOIN oauth_providers provider ON provider.id = identity.provider_id \
         WHERE provider.slug = $1",
    )
    .bind(slug)
    .fetch_one(database)
    .await
    .expect("external identity user");
    user_id
}

/// 绑定失败后不允许留下任何未撤销的会话，否则"登录失败"只是表面现象。
async fn assert_no_active_session(database: &chenxing_auth::sqlx::PgPool, user_id: i64) {
    let active: (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(database)
    .await
    .expect("active session count");
    assert_eq!(
        active.0, 0,
        "binding failure must not leave an active session"
    );
}

/// 失败审计必须归到已解析出的用户，并且不能同时留下 login 成功记录。
async fn assert_binding_failure_audit(
    database: &chenxing_auth::sqlx::PgPool,
    user_id: i64,
    slug: &str,
    reason: &str,
) {
    let failure: (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FROM audit_events WHERE actor_user_id = $1 AND action = 'login_failure' \
         AND actor_type = 'user' AND resource_type = 'external_oauth' AND resource_id = $2 \
         AND metadata->>'result' = 'failure' AND metadata->>'reason' = $3",
    )
    .bind(user_id)
    .bind(slug)
    .bind(reason)
    .fetch_one(database)
    .await
    .expect("failure audit count");
    assert_eq!(failure.0, 1, "expected one attributed login_failure event");
    let success: (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FROM audit_events WHERE actor_user_id = $1 AND action = 'login'",
    )
    .bind(user_id)
    .fetch_one(database)
    .await
    .expect("success audit count");
    assert_eq!(
        success.0, 0,
        "binding failure must not record a successful login"
    );
    // 失败审计只允许出现非凭据上下文；令牌、Cookie、state 一律不得落库。
    // 用 allowlist 而不是逐个点名禁用键，新增字段时也会被这条断言挡住。
    let unexpected: (i64,) = chenxing_auth::sqlx::query_as(
        "SELECT COUNT(*) FROM audit_events event, \
         jsonb_object_keys(event.metadata) AS metadata_key \
         WHERE event.actor_user_id = $1 AND event.action = 'login_failure' \
         AND metadata_key <> ALL($2::text[])",
    )
    .bind(user_id)
    .bind(vec![
        "result".to_owned(),
        "reason".to_owned(),
        "account_ref".to_owned(),
        "source_ip".to_owned(),
    ])
    .fetch_one(database)
    .await
    .expect("unexpected metadata key count");
    assert_eq!(
        unexpected.0, 0,
        "audit metadata must not carry credentials or unexpected fields"
    );
}

#[tokio::test]
async fn external_callback_binds_pending_request_to_created_session() {
    let mock = mock_server().await;
    let (router, database, key_directory, slug) = setup(mock).await;
    let (client_request_id, client_id, holder_cookie) = create_pending_request(&router).await;
    let (state_cookie, state) = begin_external_login(&router, &slug, &client_request_id).await;
    let response =
        complete_external_callback(&router, &slug, &state_cookie, &state, &holder_cookie).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("/oauth/consent?request_id={client_request_id}")
    );
    let session_cookie = set_cookie(&response, "chenxing_session=");
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/oauth/authorize/requests/{client_request_id}"
                ))
                .header("cookie", session_cookie)
                .body(Body::empty())
                .expect("inspect request"),
        )
        .await
        .expect("inspect response");
    assert_eq!(response.status(), StatusCode::OK);

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn external_callback_does_not_redirect_to_consent_when_pending_request_expires() {
    let mock = mock_server().await;
    let (router, database, key_directory, slug) = setup(mock).await;
    let (request_id, client_id, holder_cookie) = create_pending_request(&router).await;
    let (state_cookie, state) = begin_external_login(&router, &slug, &request_id).await;
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis_client = redis::Client::open(redis_url).expect("Redis URL");
    let mut redis_connection = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: usize = redis_connection
        .del(format!("chenxing:oauth:request:{request_id}"))
        .await
        .expect("delete pending request");

    let response =
        complete_external_callback(&router, &slug, &state_cookie, &state, &holder_cookie).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let redirect = location(&response);
    assert!(redirect.starts_with(&format!("/login?request_id={request_id}")));
    assert!(redirect.contains("external_error=oauth_request_expired"));
    assert!(!redirect.contains("/oauth/consent"));
    // 绑定失败必须 fail-closed：不下发登录 Cookie，刚建的会话已被撤销（#266）。
    assert_login_cookies_cleared(&response);
    let user_id = external_user_id(&database, &slug).await;
    assert_no_active_session(&database, user_id).await;
    assert_binding_failure_audit(&database, user_id, &slug, "oauth_request_expired").await;

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 缺少 authorization holder cookie 时绑定按 Invalid 拒绝。此前这条路径仍会下发有效
/// 登录 Cookie 并保留会话，等于错误请求换来一个可用会话（#266）。
#[tokio::test]
async fn external_callback_revokes_session_when_request_binding_is_invalid() {
    let mock = mock_server().await;
    let (router, database, key_directory, slug) = setup(mock).await;
    let (request_id, client_id, _holder_cookie) = create_pending_request(&router).await;
    let (state_cookie, state) = begin_external_login(&router, &slug, &request_id).await;

    // 只带 state cookie，不带 holder cookie：holder 校验失败 -> Invalid。
    let response = callback_with_cookies(&router, &slug, &state, &state_cookie).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let redirect = location(&response);
    assert!(redirect.starts_with(&format!("/login?request_id={request_id}")));
    assert!(redirect.contains("external_error=oauth_request_binding_failed"));
    assert!(!redirect.contains("/oauth/consent"));
    assert_login_cookies_cleared(&response);

    let user_id = external_user_id(&database, &slug).await;
    assert_no_active_session(&database, user_id).await;
    assert_binding_failure_audit(&database, user_id, &slug, "oauth_request_binding_failed").await;

    // pending 请求不能被这次失败绑定走，否则后续正常登录会被占位。
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis_client = redis::Client::open(redis_url).expect("Redis URL");
    let mut redis_connection = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let pending: Option<String> = redis_connection
        .get(format!("chenxing:oauth:request:{request_id}"))
        .await
        .expect("read pending request");
    let pending: Value = serde_json::from_str(&pending.expect("pending request still stored"))
        .expect("pending JSON");
    assert!(
        pending["session_token_hash"].is_null(),
        "invalid binding must not claim the pending request"
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    let _ = std::fs::remove_dir_all(key_directory);
}
