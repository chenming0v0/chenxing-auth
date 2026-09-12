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
    http::{Request, StatusCode, header::SET_COOKIE},
};
use chenxing_auth::{
    sessions::domain::{Session, session_token_hash},
    state::AppState,
};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

use crate::harness::HarnessBuilder;
use crate::http;

mod session_rebind;

const BINARY: &str = "oauth_request_rebinding";
const ADMIN_TOKEN: &str = "rebind-admin-token";
const REDIRECT_URI: &str = "https://rebind.example/callback";
pub(super) const REDIRECT_URI_ENCODED: &str = "https%3A%2F%2Frebind.example%2Fcallback";

pub(super) async fn setup() -> (
    Router,
    AppState,
    chenxing_auth::sqlx::PgPool,
    std::path::PathBuf,
) {
    let harness = HarnessBuilder::new(BINARY)
        .admin_token(ADMIN_TOKEN)
        .bootstrap_owner()
        .build()
        .await;
    (
        harness.router,
        harness.state,
        harness.database,
        harness.key_directory,
    )
}

pub(super) fn request_id(location: &str) -> String {
    Url::parse(&format!("http://localhost{location}"))
        .expect("request URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request_id in location")
}

/// 从 Set-Cookie 中取出 `name=value`，用于拼装后续请求的 Cookie 头。
pub(super) fn set_cookie_pair(response: &axum::response::Response, name: &str) -> Option<String> {
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

pub(super) fn session_cookie(session: &Session) -> String {
    format!(
        "chenxing_session={}; chenxing_csrf={}",
        session.token, session.csrf_token
    )
}

pub(super) async fn create_user(router: &Router, label: &str) -> i64 {
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
    http::json_body(response).await["id"]
        .as_i64()
        .expect("user id")
}

pub(super) async fn create_client(router: &Router) -> String {
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
    http::json_body(response).await["client_id"]
        .as_str()
        .expect("client id")
        .to_owned()
}

pub(super) async fn persisted_session(state: &AppState, user_id: i64) -> Session {
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("session domain object");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    session
}

async fn grant_consent(database: &chenxing_auth::sqlx::PgPool, user_id: i64, client_id: &str) {
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE
         SET scopes = EXCLUDED.scopes, revoked_at = NULL, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(client_id)
    .bind(serde_json::json!(["openid", "profile"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(database)
    .await
    .expect("grant OAuth consent");
}

fn authorize_query(client_id: &str, extra: &str) -> String {
    format!(
        "client_id={client_id}&redirect_uri={REDIRECT_URI_ENCODED}&response_type=code&scope=openid%20profile&state=prompt-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256{extra}"
    )
}

fn callback_parameter(location: &str, name: &str) -> Option<String> {
    Url::parse(location)
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// 未登录浏览器发起授权：拿到 `request_id` 与 holder Cookie。
pub(super) async fn start_unauthenticated_authorization(
    router: &Router,
    client_id: &str,
) -> (String, String) {
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
    let target = http::location(&response);
    assert!(
        target.starts_with("/login?"),
        "unauthenticated authorize must land on the SPA login page, got {target}"
    );
    let holder = set_cookie_pair(&response, "chenxing_authz_holder")
        .expect("authorize must issue the holder cookie");
    (request_id(&target), holder)
}

pub(super) async fn bind(
    router: &Router,
    request_id: &str,
    cookie: &str,
    csrf: &str,
) -> StatusCode {
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

pub(super) async fn inspect(router: &Router, request_id: &str, cookie: &str) -> StatusCode {
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

pub(super) async fn cleanup(
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

#[tokio::test]
async fn prompt_none_returns_protocol_errors_without_entering_ui_for_get_or_post() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "prompt-none").await;
    let client_id = create_client(&router).await;
    let query = authorize_query(&client_id, "&prompt=none");

    for method in ["GET", "POST"] {
        let mut builder = Request::builder().method(method).uri(if method == "GET" {
            format!("/oauth/authorize?{query}")
        } else {
            "/oauth/authorize".to_owned()
        });
        let body = if method == "POST" {
            builder = builder.header("content-type", "application/x-www-form-urlencoded");
            Body::from(query.clone())
        } else {
            Body::empty()
        };
        let response = router
            .clone()
            .oneshot(builder.body(body).expect("prompt=none authorize request"))
            .await
            .expect("prompt=none authorize response");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let target = http::location(&response);
        assert_eq!(
            callback_parameter(&target, "error").as_deref(),
            Some("login_required")
        );
        assert!(set_cookie_pair(&response, "chenxing_authz_holder").is_none());
    }

    let session = persisted_session(&state, user_id).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/oauth/authorize?{query}"))
                .header("cookie", session_cookie(&session))
                .body(Body::empty())
                .expect("prompt=none authorize request with session"),
        )
        .await
        .expect("prompt=none authorize response with session");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let target = http::location(&response);
    assert_eq!(
        callback_parameter(&target, "error").as_deref(),
        Some("consent_required")
    );
    assert!(set_cookie_pair(&response, "chenxing_authz_holder").is_none());

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}

#[tokio::test]
async fn prompt_and_max_age_select_the_required_interaction_with_existing_consent() {
    let (router, state, database, key_directory) = setup().await;
    let user_id = create_user(&router, "prompt-interaction").await;
    let client_id = create_client(&router).await;
    grant_consent(&database, user_id, &client_id).await;
    let session = persisted_session(&state, user_id).await;
    let cookie = session_cookie(&session);

    for (extra, expected_path) in [
        ("&prompt=consent", "/oauth/consent"),
        ("&prompt=select_account", "/oauth/account"),
        ("&prompt=select_account%20consent", "/oauth/account"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/oauth/authorize?{}",
                        authorize_query(&client_id, extra)
                    ))
                    .header("accept", "text/html")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .expect("interactive authorize request"),
            )
            .await
            .expect("interactive authorize response");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            Url::parse(&format!("http://localhost{}", http::location(&response)))
                .expect("SPA interaction URL")
                .path(),
            expected_path
        );
        assert!(set_cookie_pair(&response, "chenxing_authz_holder").is_some());
    }

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?{}",
                    authorize_query(&client_id, "&prompt=none")
                ))
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("silent authorize request"),
        )
        .await
        .expect("silent authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(callback_parameter(&http::location(&response), "code").is_some());
    assert!(set_cookie_pair(&response, "chenxing_authz_holder").is_none());

    cleanup(&database, &client_id, &[user_id], key_directory).await;
}
