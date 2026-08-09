//! 集成测试：OAuth pending 请求的受控重绑（#270）。
//!
//! 回归的是一个死锁：pending 请求绑定旧 Session 后，会话过期重新登录或切换账号
//! 都会产生新 Session，而 URL 里的 `request_id` 不变。旧实现在 bind 端点上固定
//! 返回 `401 invalid_session`，前端跟着 401 跳登录页，登录后又被送回确认页，
//! 形成登录循环。
//!
//! 现在的语义：holder Cookie 是所有权凭据，Session 绑定是派生状态。holder +
//! CSRF + 有效会话三者通过时允许重绑到调用者当前会话，重绑幂等且走 CAS。
//! 安全边界不变——没有 holder Cookie 的第三方即使持有有效会话仍然被拒。

use axum::{
    Router,
    body::Body,
    http::{
        Request, StatusCode,
        header::{LOCATION, SET_COOKIE},
    },
};
use chenxing_auth::{
    api,
    config::Config,
    sessions::domain::{Session, session_token_hash},
    state::AppState,
};
use serde_json::Value;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/oauth_flow.rs"]
mod oauth_flow;

const BINARY: &str = "oauth_request_rebinding";
const ADMIN_TOKEN: &str = "rebind-admin-token";
const REDIRECT_URI: &str = "https://rebind.example/callback";
const REDIRECT_URI_ENCODED: &str = "https%3A%2F%2Frebind.example%2Fcallback";

async fn setup() -> (
    Router,
    AppState,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool(BINARY, &database_url).await;
    let key_directory = std::env::temp_dir().join(format!("chenxing-{BINARY}-{}", Uuid::new_v4()));
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.admin_token = ADMIN_TOKEN.to_owned();
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    let state = AppState::new_with_pool(config, database.clone())
        .await
        .expect("state");
    let router = api::router(state.clone());
    oauth_flow::ensure_owner_bootstrapped(&router, BINARY).await;
    (router, state, database, key_directory)
}

async fn json(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("JSON")
}

fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("location header")
        .to_owned()
}

fn request_id(location: &str) -> String {
    Url::parse(&format!("http://localhost{location}"))
        .expect("request URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request_id in location")
}

/// 从 Set-Cookie 中取出 `name=value`，用于拼装后续请求的 Cookie 头。
fn set_cookie_pair(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .find_map(|value| {
            let pair = value.to_str().ok()?.split(';').next()?.trim();
            pair.starts_with(&format!("{name}="))
                .then(|| pair.to_owned())
        })
}

fn session_cookie(session: &Session) -> String {
    format!(
        "chenxing_session={}; chenxing_csrf={}",
        session.token, session.csrf_token
    )
}

async fn create_user(router: &Router, label: &str) -> i64 {
    let suffix = Uuid::new_v4().simple().to_string();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": format!("{label}-{suffix}"),
                        "email": format!("{label}-{suffix}@example.com"),
                        "password": "correct horse battery",
                    })
                    .to_string(),
                ))
                .expect("admin user creation request"),
        )
        .await
        .expect("admin user creation response");
    assert_eq!(response.status(), StatusCode::CREATED);
    json(response).await["id"].as_i64().expect("user id")
}

async fn create_client(router: &Router) -> String {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/clients")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "Rebinding Client",
                        "redirect_uris": [REDIRECT_URI],
                        "scopes": ["openid", "profile"]
                    })
                    .to_string(),
                ))
                .expect("client request"),
        )
        .await
        .expect("client response");
    assert_eq!(response.status(), StatusCode::CREATED);
    json(response).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned()
}

async fn persisted_session(state: &AppState, user_id: i64) -> Session {
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("session domain object");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    session
}

/// 未登录浏览器发起授权：拿到 `request_id` 与 holder Cookie。
async fn start_unauthenticated_authorization(router: &Router, client_id: &str) -> (String, String) {
    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri={REDIRECT_URI_ENCODED}&response_type=code&scope=openid%20profile&state=rebind-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("accept", "text/html")
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    let target = location(&response);
    assert!(
        target.starts_with("/login?"),
        "unauthenticated authorize must land on the SPA login page, got {target}"
    );
    let holder = set_cookie_pair(&response, "chenxing_authz_holder")
        .expect("authorize must issue the holder cookie");
    (request_id(&target), holder)
}

async fn bind(router: &Router, request_id: &str, cookie: &str, csrf: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/oauth/authorize/requests/{request_id}/bind"
                ))
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .expect("bind request"),
        )
        .await
        .expect("bind response")
        .status()
}

async fn inspect(router: &Router, request_id: &str, cookie: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("inspect request"),
        )
        .await
        .expect("inspect response")
        .status()
}

async fn cleanup(
    database: &chenxing_auth::sqlx::PgPool,
    client_id: &str,
    user_ids: &[i64],
    key_directory: std::path::PathBuf,
) {
    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(database)
        .await
        .expect("cleanup client");
    for user_id in user_ids {
        chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(database)
            .await
            .expect("cleanup user");
    }
    let _ = std::fs::remove_dir_all(key_directory);
}

/// 会话过期恢复：绑定 → 会话撤销 → 重新登录得到新会话 → 同一 holder 重绑成功。
///
/// 旧行为在最后一步固定 `401 invalid_session`，前端据此跳登录页，形成循环。
#[tokio::test]
async fn expired_session_rebinds_after_relogin_and_can_still_approve() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "rebind-expiry").await;
    let client_id = create_client(&router).await;
    let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;

    // 第一次登录：绑定成功。
    let first_session = persisted_session(&state, user_id).await;
    let first_cookie = format!("{}; {holder}", session_cookie(&first_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &first_cookie,
            &first_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT
    );

    // 会话过期 / 被撤销：pending 记录里仍留着旧会话摘要。
    state
        .sessions
        .revoke(&first_session.token)
        .await
        .expect("revoke first session");

    // 重新登录得到全新会话，holder Cookie 仍在浏览器里（TTL 与 pending 对齐）。
    let second_session = persisted_session(&state, user_id).await;
    let second_cookie = format!("{}; {holder}", session_cookie(&second_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &second_cookie,
            &second_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT,
        "a fresh session with a valid holder cookie must be able to rebind (#270)"
    );

    // 重绑后的会话摘要必须指向新会话：授权码会继承这个绑定。
    let pending = state
        .authorization_requests
        .find(&request_id)
        .await
        .expect("find pending request")
        .expect("pending request still exists");
    assert_eq!(
        pending.session_token_hash.as_deref(),
        Some(session_token_hash(&second_session.token).as_str())
    );

    // 新会话可以读取并批准，流程真正恢复而不只是 bind 返回 204。
    assert_eq!(
        inspect(&router, &request_id, &second_cookie).await,
        StatusCode::OK
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &second_cookie)
                .header("x-csrf-token", &second_session.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("approve request"),
        )
        .await
        .expect("approve response");
    assert_eq!(response.status(), StatusCode::OK);
    let approved = json(response).await;
    assert!(
        approved["redirect_to"]
            .as_str()
            .is_some_and(|value| value.contains("code=")),
        "approval after rebinding must issue an authorization code"
    );

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}

/// 切换账号：同一浏览器登出后换另一个账号登录，pending 请求重绑到新账号会话。
///
/// 这是「使用其他辰星通行证」的正常流程，不是攻击：holder 证明还是同一个浏览器。
#[tokio::test]
async fn account_switch_rebinds_pending_request_to_the_second_account() {
    let (router, state, database, key_directory) = setup().await;
    let first_user = create_user(&router, "rebind-switch-a").await;
    let second_user = create_user(&router, "rebind-switch-b").await;
    let client_id = create_client(&router).await;
    let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;

    let first_session = persisted_session(&state, first_user).await;
    let first_cookie = format!("{}; {holder}", session_cookie(&first_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &first_cookie,
            &first_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT
    );

    // 切换账号：第二个用户在同一浏览器登录（holder Cookie 不变）。
    let second_session = persisted_session(&state, second_user).await;
    let second_cookie = format!("{}; {holder}", session_cookie(&second_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &second_cookie,
            &second_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT,
        "switching accounts in the same browser must rebind, not deadlock (#270)"
    );
    assert_eq!(
        state
            .authorization_requests
            .find(&request_id)
            .await
            .expect("find pending request")
            .expect("pending request exists")
            .session_token_hash
            .as_deref(),
        Some(session_token_hash(&second_session.token).as_str())
    );

    // 第一个账号的会话此时不再持有该请求：读取被拒，不能替第二个账号做决定。
    assert_eq!(
        inspect(&router, &request_id, &first_cookie).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        inspect(&router, &request_id, &second_cookie).await,
        StatusCode::OK
    );

    cleanup(
        &database,
        &client_id,
        &[first_user, second_user],
        key_directory,
    )
    .await;
}

/// 安全边界不变：没有 holder Cookie 的第三方账号即使持有有效会话也不能重绑，
/// 且被拒的尝试不得改动已有绑定。这是重绑语义安全性的核心断言。
#[tokio::test]
async fn third_party_session_without_holder_cookie_cannot_rebind() {
    let (router, state, database, key_directory) = setup().await;
    let victim = create_user(&router, "rebind-victim").await;
    let attacker = create_user(&router, "rebind-attacker").await;
    let client_id = create_client(&router).await;
    let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;

    let victim_session = persisted_session(&state, victim).await;
    let victim_cookie = format!("{}; {holder}", session_cookie(&victim_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &victim_cookie,
            &victim_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT
    );

    // 攻击者拿到泄露的 request_id，持有自己的有效会话，但没有 holder Cookie。
    let attacker_session = persisted_session(&state, attacker).await;
    let attacker_cookie = session_cookie(&attacker_session);
    assert_eq!(
        bind(
            &router,
            &request_id,
            &attacker_cookie,
            &attacker_session.csrf_token
        )
        .await,
        StatusCode::FORBIDDEN,
        "a valid session without the holder cookie must never claim a pending request"
    );

    // 伪造的 holder 同样被拒。
    let forged_cookie = format!("{attacker_cookie}; chenxing_authz_holder=forged-holder-value");
    assert_eq!(
        bind(
            &router,
            &request_id,
            &forged_cookie,
            &attacker_session.csrf_token
        )
        .await,
        StatusCode::FORBIDDEN
    );

    // 受害者的绑定完好无损。
    assert_eq!(
        state
            .authorization_requests
            .find(&request_id)
            .await
            .expect("find pending request")
            .expect("pending request exists")
            .session_token_hash
            .as_deref(),
        Some(session_token_hash(&victim_session.token).as_str())
    );
    assert_eq!(
        inspect(&router, &request_id, &attacker_cookie).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        inspect(&router, &request_id, &victim_cookie).await,
        StatusCode::OK
    );

    cleanup(&database, &client_id, &[victim, attacker], key_directory).await;
}

/// 已登录用户首次授权也必须拿到 holder Cookie（#270）。
///
/// 否则这条路径创建的 pending 请求永远无法重绑：会话在确认前过期后，用户
/// 只能在登录页与确认页之间打转。
#[tokio::test]
async fn authenticated_consent_redirect_issues_holder_cookie_and_supports_rebinding() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "rebind-authenticated").await;
    let client_id = create_client(&router).await;

    // 已登录浏览器直接命中 authorize：应重定向到确认页并下发 holder。
    let first_session = persisted_session(&state, user_id).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?client_id={client_id}&redirect_uri={REDIRECT_URI_ENCODED}&response_type=code&scope=openid%20profile&state=rebind-authenticated-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
                ))
                .header("accept", "text/html")
                .header("cookie", session_cookie(&first_session))
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    let target = location(&response);
    assert!(
        target.starts_with("/oauth/consent?"),
        "an authenticated first-time authorization must land on the consent page, got {target}"
    );
    let holder = set_cookie_pair(&response, "chenxing_authz_holder").expect(
        "the authenticated consent redirect must also issue the holder cookie so the request stays rebindable (#270)",
    );
    let request_id = request_id(&target);

    // 会话在确认前过期，用户重新登录：新会话仍能重绑并继续。
    state
        .sessions
        .revoke(&first_session.token)
        .await
        .expect("revoke session");
    let second_session = persisted_session(&state, user_id).await;
    let second_cookie = format!("{}; {holder}", session_cookie(&second_session));
    assert_eq!(
        bind(
            &router,
            &request_id,
            &second_cookie,
            &second_session.csrf_token
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        inspect(&router, &request_id, &second_cookie).await,
        StatusCode::OK
    );

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}

/// 幂等：同一会话重复绑定返回 204 且不改动载荷；请求被消费后绑定按过期处理。
#[tokio::test]
async fn repeated_bind_is_idempotent_and_consumed_request_reports_expired() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "rebind-idempotent").await;
    let client_id = create_client(&router).await;
    let (request_id, holder) = start_unauthenticated_authorization(&router, &client_id).await;

    let session = persisted_session(&state, user_id).await;
    let cookie = format!("{}; {holder}", session_cookie(&session));
    for _ in 0..3 {
        assert_eq!(
            bind(&router, &request_id, &cookie, &session.csrf_token).await,
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        state
            .authorization_requests
            .find(&request_id)
            .await
            .expect("find pending request")
            .expect("pending request exists")
            .session_token_hash
            .as_deref(),
        Some(session_token_hash(&session.token).as_str())
    );

    // 消费掉请求（拒绝），之后的绑定必须是 400 过期，而不是 401/403 或静默成功。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &session.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"deny"}"#))
                .expect("deny request"),
        )
        .await
        .expect("deny response");
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        bind(&router, &request_id, &cookie, &session.csrf_token).await,
        StatusCode::BAD_REQUEST
    );
    assert!(
        state
            .authorization_requests
            .find(&request_id)
            .await
            .expect("find consumed request")
            .is_none(),
        "a failed bind must not resurrect a consumed pending request"
    );

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}
