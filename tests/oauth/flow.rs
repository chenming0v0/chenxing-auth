use axum::{
    body::Body,
    http::{Request, StatusCode, header::LOCATION},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chenxing_auth::sessions::domain::Session;
use chenxing_auth::{
    api,
    oauth::{
        authorization::ValidatedAuthorizationRequest,
        code::AuthorizationCode,
        handlers::issue_authorization_code_result,
        refresh::RefreshToken,
        refresh_store::{RefreshTokenStore, RotationOutcome},
        store::AuthorizationCodeStore,
    },
    state::AppState,
};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

use crate::oauth_flow as support;

mod code_consume;

// 迁移不再种子默认套餐，需要配额计量的用例必须自己播种（见 support/plan_fixtures.rs）。
use crate::plan_fixtures;

use support::{
    create_test_client, disable_user, ensure_owner_bootstrapped, json_body, register_test_user,
    session_cookie, test_state,
};

/// #508：无会话绑定的授权码在 Token 端点 fail-closed，直存授权码走兑换路径的
/// 测试必须先把码绑定到一条已持久化的浏览器会话上。
pub(super) async fn bound_session_token(state: &AppState, user_id: i64) -> String {
    let mut session =
        Session::new(user_id.to_string(), std::time::Duration::from_secs(3600)).expect("session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    session.token
}

pub(super) fn test_issuer(
    state: &AppState,
) -> std::sync::Arc<chenxing_auth::settings::IssuerSnapshot> {
    state
        .issuer
        .current()
        .expect("test state has a loaded issuer")
}

#[tokio::test]
async fn disabled_user_session_cannot_authorize_or_submit_consent() {
    let (state, database, key_directory) = test_state("oauth_flow").await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&router, &suffix).await;
    let (client_id, _client_secret) = create_test_client(&router, "flow-admin-token").await;
    let mut session =
        Session::new(user_id.to_string(), std::time::Duration::from_secs(3600)).expect("session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    let cookie = session_cookie(&session);
    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fdisabled.example%2Fcallback&response_type=code&scope=openid%20profile&state=disabled-state&nonce=disabled-nonce&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("accept", "text/html")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("authorize request"),
        )
        .await
        .expect("authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let consent_location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("consent location")
        .to_owned();
    assert!(consent_location.starts_with("/oauth/consent?request_id="));
    let request_id = Url::parse(&format!("http://localhost{consent_location}"))
        .expect("consent URL")
        .query_pairs()
        .find(|(key, _)| key == "request_id")
        .map(|(_, value)| value.into_owned())
        .expect("request id");

    disable_user(&database, user_id).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("accept", "text/html")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("disabled authorize request"),
        )
        .await
        .expect("disabled authorize response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("/login?request_id="))
    );

    // A disabled user's session can no longer inspect the pending request over JSON.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("disabled inspect request"),
        )
        .await
        .expect("disabled inspect response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Nor submit a JSON consent decision.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &session.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"decision": "approve"}).to_string(),
                ))
                .expect("disabled consent request"),
        )
        .await
        .expect("disabled consent response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn disabled_user_cannot_exchange_oauth_credentials_without_consuming_them() {
    let (state, database, key_directory) = test_state("oauth_flow").await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&router, "flow-admin-token").await;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let code = AuthorizationCode::new_with_nonce(
        client_id.clone(),
        "https://disabled.example/callback".to_owned(),
        user_id.to_string(),
        vec!["openid".to_owned(), "profile".to_owned()],
        challenge,
        Some("disabled-nonce".to_owned()),
        Some(bound_session_token(&state, user_id).await),
    )
    .with_issuer_generation(test_issuer(&state).generation());
    let mut refresh = RefreshToken::new(
        client_id.clone(),
        user_id.to_string(),
        vec!["openid".to_owned(), "profile".to_owned()],
    );
    refresh.issuer_generation = Some(
        state
            .issuer
            .current()
            .expect("test state has a loaded issuer")
            .generation(),
    );
    state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    state
        .refresh_tokens
        .save(&refresh)
        .await
        .expect("save refresh token");
    disable_user(&database, user_id).await;
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fdisabled.example%2Fcallback&code_verifier={verifier}",
                    code.value
                )))
                .expect("code exchange request"),
        )
        .await
        .expect("code exchange response");
    assert_ne!(response.status(), StatusCode::OK);
    assert!(
        state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("find authorization code")
            .is_some(),
        "disabled-user rejection must not consume the authorization code"
    );

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}",
                    refresh.value
                )))
                .expect("refresh request"),
        )
        .await
        .expect("refresh response");
    assert_ne!(response.status(), StatusCode::OK);
    assert!(
        state
            .refresh_tokens
            .find(&refresh.value)
            .await
            .expect("find refresh token")
            .is_some(),
        "disabled-user rejection must not consume the refresh token"
    );

    let issuer = state
        .issuer
        .current()
        .expect("test state has a loaded issuer");
    let nonce = "disabled-nonce";
    let scopes = ["openid".to_owned(), "profile".to_owned()];
    let response = chenxing_auth::oauth::response::issue_token_response(
        &state,
        chenxing_auth::oauth::response::TokenIssueParams {
            issuer: issuer.issuer(),
            user_id: &user_id.to_string(),
            client_id: &client_id,
            scopes: &scopes,
            refresh_token: None,
            nonce: Some(nonce),
            auth_time: None,
        },
    )
    .await;
    assert_ne!(response.status(), StatusCode::OK);

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}

async fn refresh_token_count_for_client(state: &AppState, client_id: &str) -> usize {
    let mut connection = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("chenxing:oauth:refresh:*")
        .query_async(&mut connection)
        .await
        .expect("refresh token keys");
    let mut count = 0;
    for key in keys {
        let payload: Option<String> = connection.get(key).await.expect("refresh token payload");
        if payload
            .as_deref()
            .and_then(|value| serde_json::from_str::<RefreshToken>(value).ok())
            .is_some_and(|refresh| refresh.client_id == client_id)
        {
            count += 1;
        }
    }
    count
}

/// 保留一个 TCP 端口号后立刻释放：得到一个几乎肯定连不上的 Redis 地址，
/// 用来模拟「凭据已经写进 Redis，但补偿删除失败」。
fn unavailable_redis_client() -> redis::Client {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve Redis port");
    let port = listener
        .local_addr()
        .expect("reserved Redis address")
        .port();
    drop(listener);
    redis::Client::open(format!("redis://127.0.0.1:{port}/")).expect("Redis URL")
}

async fn post_refresh(router: &axum::Router, basic: &str, refresh_value: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh_value}"
                )))
                .expect("refresh request"),
        )
        .await
        .expect("refresh response")
        .status()
}

/// Issue #293：提交一个已经被消费掉的 refresh token 一律撤销整个 family，
/// 不存在「刚刚消费过所以算并发」的宽限窗口。
///
/// 这个窗口曾经存在（Issue #278），代价是攻击者窃取凭据后只要紧跟着合法客户端
/// 的刷新提交同一个值，就能得到一次不触发 family 撤销的免费尝试；而 family
/// 撤销是检测凭据泄露的唯一手段。单次使用就按单次使用执行：正常客户端轮换后
/// 手里已经是新值，重复提交旧值要么是客户端并发 bug，要么是泄露。
#[tokio::test]
async fn resubmitting_a_consumed_refresh_token_revokes_the_family() {
    let (state, database, key_directory) = test_state("oauth_flow").await;
    let setup_router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&setup_router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&setup_router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&setup_router, "flow-admin-token").await;
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let original = RefreshToken::new(
        client_id.clone(),
        user_id.to_string(),
        vec!["openid".to_owned()],
    );
    let rotated = original.rotate(vec!["openid".to_owned()]);
    state
        .refresh_tokens
        .save(&original)
        .await
        .expect("save original refresh token");
    // 直接用 store 模拟一次已经完成的轮换：original 被消费、rotated 成为活成员。
    assert_eq!(
        state
            .refresh_tokens
            .rotate_if_matches(&original.value, &original, &rotated)
            .await
            .expect("simulate a completed rotation"),
        RotationOutcome::Rotated
    );

    // 再次提交 original：立刻按 replay 处置，整个 family 一起失效。
    assert_eq!(
        post_refresh(&setup_router, &basic, &original.value).await,
        StatusCode::BAD_REQUEST
    );
    assert!(
        state
            .refresh_tokens
            .find(&rotated.value)
            .await
            .expect("find the successor token")
            .is_none(),
        "resubmitting a consumed token must revoke the whole token family"
    );

    // 重复提交是幂等的：family 已经撤销，只得到普通 invalid_grant。
    assert_eq!(
        post_refresh(&setup_router, &basic, &original.value).await,
        StatusCode::BAD_REQUEST
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(&database)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&database)
        .await
        .expect("cleanup user");
    let _ = std::fs::remove_dir_all(key_directory);
}
