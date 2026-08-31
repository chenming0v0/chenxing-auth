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

// 迁移不再种子默认套餐，需要配额计量的用例必须自己播种（见 support/plan_fixtures.rs）。
use crate::plan_fixtures;

use support::{
    create_test_client, disable_user, ensure_owner_bootstrapped, json_body, register_test_user,
    session_cookie, test_state,
};

/// #508：无会话绑定的授权码在 Token 端点 fail-closed，直存授权码走兑换路径的
/// 测试必须先把码绑定到一条已持久化的浏览器会话上。
async fn bound_session_token(state: &AppState, user_id: i64) -> String {
    let mut session =
        Session::new(user_id.to_string(), std::time::Duration::from_secs(3600)).expect("session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    session.token
}

fn test_issuer(state: &AppState) -> std::sync::Arc<chenxing_auth::settings::IssuerSnapshot> {
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

#[tokio::test]
async fn refresh_token_remains_reusable_when_access_token_issuance_fails() {
    let (mut state, database, key_directory) = test_state("oauth_flow").await;
    let setup_router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&setup_router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&setup_router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&setup_router, "flow-admin-token").await;
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
        .refresh_tokens
        .save(&refresh)
        .await
        .expect("save refresh token");
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(&client_id)
    .bind(serde_json::json!(["openid", "profile"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(&database)
    .await
    .expect("save refresh token consent");
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));

    // u64::MAX 让 access token 的 `exp` 计算溢出，模拟签发失败（#112 起
    // 令牌有效期与浏览器会话 TTL 解耦，必须改动 access_token_ttl_seconds）。
    state.config.access_token_ttl_seconds = u64::MAX;
    let failing_router = api::router(state.clone());
    let response = failing_router
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
                .expect("failed refresh request"),
        )
        .await
        .expect("failed refresh response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        state
            .refresh_tokens
            .find(&refresh.value)
            .await
            .expect("find refresh after issuance failure")
            .is_some(),
        "failed token issuance must not consume the refresh token"
    );

    state.config.access_token_ttl_seconds = 3600;
    let retry_router = api::router(state.clone());
    let response = retry_router
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
                .expect("retry refresh request"),
        )
        .await
        .expect("retry refresh response");
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed = json_body(response).await;
    let next_refresh = refreshed["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_owned();
    assert!(
        state
            .refresh_tokens
            .find(&refresh.value)
            .await
            .expect("find consumed refresh after retry")
            .is_none()
    );
    assert!(
        state
            .refresh_tokens
            .find(&next_refresh)
            .await
            .expect("find rotated refresh after retry")
            .is_some()
    );

    let response = retry_router
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
                .expect("duplicate refresh request"),
        )
        .await
        .expect("duplicate refresh response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let duplicate = json_body(response).await;
    assert_eq!(duplicate["error"].as_str(), Some("invalid_grant"));

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

/// Issue #409：管理端 TOTP 重置的撤销步（`reset_user_totp_factor` 调用的
/// `revoke_all_for_user`）只推进 `session_epoch`，此前 Refresh Token 兑换不做
/// 凭据代际判定，旧 Refresh Token 在重置后仍能持续换取 access token。修复后
/// token 签发时 stamp 当前 epoch，兑换时与用户当前 epoch 比对：重置推进 epoch，
/// 该用户全部已签发 Refresh Token 随之失效，且拒绝发生在消费之前。
#[tokio::test]
async fn totp_reset_revocation_invalidates_outstanding_refresh_tokens() {
    let (state, database, key_directory) = test_state("oauth_flow").await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&router, "flow-admin-token").await;
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(&client_id)
    .bind(serde_json::json!(["openid"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(&database)
    .await
    .expect("save refresh token consent");
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let code = AuthorizationCode::new_with_nonce(
        client_id.clone(),
        "https://reset.example/callback".to_owned(),
        user_id.to_string(),
        vec!["openid".to_owned()],
        challenge,
        Some("reset-nonce".to_owned()),
        Some(bound_session_token(&state, user_id).await),
    )
    .with_issuer_generation(test_issuer(&state).generation());
    state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");

    // 真实授权码流程签发一枚 Refresh Token：它 stamp 了签发时刻的凭据代际。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Freset.example%2Fcallback&code_verifier={verifier}",
                    code.value
                )))
                .expect("code exchange request"),
        )
        .await
        .expect("code exchange response");
    assert_eq!(response.status(), StatusCode::OK);
    let refresh_value = json_body(response).await["refresh_token"]
        .as_str()
        .expect("issued refresh token")
        .to_owned();

    // 管理端 TOTP 重置的撤销步（admin/factor_handlers::reset_user_totp_factor）：
    // revoke_all_for_user 推进 session_epoch，Cookie 会话与全部 Refresh Token
    // 在同一凭据水位上一起失效。
    state
        .sessions
        .revoke_all_for_user(user_id)
        .await
        .expect("revoke all user credentials");

    // 重置后：签发于旧代际的 Refresh Token 必须被拒绝。
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh_value}"
                )))
                .expect("rejected refresh request"),
        )
        .await
        .expect("rejected refresh response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["error"].as_str(),
        Some("invalid_grant")
    );
    // 代际拒绝发生在消费（CAS 轮换）之前：token 必须仍然存在，证明拒绝的
    // 原因是凭据代际被撤销，而不是重放检测或 family 撤销删掉了它。
    assert!(
        state
            .refresh_tokens
            .find(&refresh_value)
            .await
            .expect("find rejected refresh token")
            .is_some(),
        "epoch rejection must not consume the refresh token"
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

#[tokio::test]
async fn authorization_code_is_restored_when_token_issuance_fails() {
    let (mut state, database, key_directory) = test_state("oauth_flow").await;
    let setup_router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&setup_router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&setup_router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&setup_router, "flow-admin-token").await;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let code = AuthorizationCode::new_with_nonce(
        client_id.clone(),
        "https://restore.example/callback".to_owned(),
        user_id.to_string(),
        vec!["openid".to_owned(), "profile".to_owned()],
        challenge,
        Some("restore-nonce".to_owned()),
        Some(bound_session_token(&state, user_id).await),
    )
    .with_issuer_generation(test_issuer(&state).generation());
    // 授权码兑换在 CAS 前校验 consent（Issue #417），直存授权码必须补 consent 行。
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(&client_id)
    .bind(serde_json::json!(["openid", "profile"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(&database)
    .await
    .expect("save code exchange consent");
    state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));

    // 同上：溢出 access token 有效期以触发签发失败。
    state.config.access_token_ttl_seconds = u64::MAX;
    let failing_router = api::router(state.clone());
    let response = failing_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Frestore.example%2Fcallback&code_verifier={verifier}",
                    code.value
                )))
                .expect("failed code exchange request"),
        )
        .await
        .expect("failed code exchange response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("find restored authorization code")
            .is_some(),
        "token issuance failure must restore the consumed authorization code"
    );
    assert_eq!(
        refresh_token_count_for_client(&state, &client_id).await,
        0,
        "token issuance failure must not leave an orphan refresh token"
    );

    state.config.access_token_ttl_seconds = 3600;
    let retry_router = api::router(state.clone());
    let response = retry_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Frestore.example%2Fcallback&code_verifier={verifier}",
                    code.value
                )))
                .expect("retry code exchange request"),
        )
        .await
        .expect("retry code exchange response");
    assert_eq!(response.status(), StatusCode::OK);
    let token = json_body(response).await;
    assert!(token["access_token"].as_str().is_some());
    assert!(token["refresh_token"].as_str().is_some());
    assert_eq!(refresh_token_count_for_client(&state, &client_id).await, 1);
    assert!(
        state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("find consumed authorization code")
            .is_none(),
        "successfully retried authorization code must remain consumed"
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

/// Issue #290：补偿删除 Refresh Token 失败时必须 fail-closed，保持授权码已消费。
///
/// 否则同一次授权可以再换出第二个 Refresh Token，两者 family 不同，
/// 任意一个被 replay 撤销都杀不掉另一个。
#[tokio::test]
async fn authorization_code_stays_consumed_when_refresh_cleanup_fails() {
    let (mut state, database, key_directory) = test_state("oauth_flow").await;
    let setup_router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&setup_router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&setup_router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&setup_router, "flow-admin-token").await;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let code = AuthorizationCode::new_with_nonce(
        client_id.clone(),
        "https://restore.example/callback".to_owned(),
        user_id.to_string(),
        vec!["openid".to_owned()],
        challenge,
        None,
        Some(bound_session_token(&state, user_id).await),
    )
    .with_issuer_generation(test_issuer(&state).generation());
    // 授权码兑换在 CAS 前校验 consent（Issue #417），直存授权码必须补 consent 行。
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(&client_id)
    .bind(serde_json::json!(["openid"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(&database)
    .await
    .expect("save code exchange consent");
    state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));

    // Refresh Token store 不可用：授权码已被 CAS 消费，随后的补偿删除也失败。
    let healthy_refresh_tokens = state.refresh_tokens.clone();
    state.refresh_tokens = RefreshTokenStore::new(unavailable_redis_client());
    let failing_router = api::router(state.clone());
    let response = failing_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Frestore.example%2Fcallback&code_verifier={verifier}",
                    code.value
                )))
                .expect("failed code exchange request"),
        )
        .await
        .expect("failed code exchange response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    state.refresh_tokens = healthy_refresh_tokens;
    assert!(
        state
            .authorization_codes
            .find(&code.value)
            .await
            .expect("look up the authorization code")
            .is_none(),
        "a failed refresh cleanup must not restore a redeemable authorization code"
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

#[tokio::test]
async fn authorization_code_store_failure_does_not_consume_oauth_quota() {
    let (mut state, database, key_directory) = test_state("oauth_flow").await;
    let setup_router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&setup_router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&setup_router, &suffix).await;
    let (client_id, _client_secret) = create_test_client(&setup_router, "flow-admin-token").await;
    chenxing_auth::sqlx::query("UPDATE oauth_clients SET owner_user_id = $1 WHERE client_id = $2")
        .bind(user_id)
        .bind(&client_id)
        .execute(&database)
        .await
        .expect("bind client owner");

    // 计量只在存在生效套餐时发生，所以这个用例必须显式挂一个私有套餐；
    // 否则「授权码写失败不烧配额」根本没有配额可烧，断言会退化成空转。
    plan_fixtures::assign_private_plan(
        &database,
        user_id,
        plan_fixtures::PlanLimits::legacy_default(),
    )
    .await;
    let effective = state
        .plans
        .effective_plan_for_user(user_id)
        .await
        .expect("effective plan")
        .expect("the fixture plan must be the effective plan");
    let limits = Some(effective.plan.auth_quota_limits());
    let before = state
        .oauth_quotas
        .snapshot(&client_id, limits)
        .await
        .expect("quota before failed authorization");
    assert_eq!(before.daily_limit, Some(2_500));

    state.authorization_codes = AuthorizationCodeStore::new(
        redis::Client::open("redis://127.0.0.1:1").expect("invalid Redis endpoint is parseable"),
    );
    let result = issue_authorization_code_result(
        &state,
        test_issuer(&state).as_ref(),
        user_id.to_string(),
        ValidatedAuthorizationRequest {
            client_id: client_id.clone(),
            redirect_uri: "https://disabled.example/callback".to_owned(),
            scopes: vec!["openid".to_owned()],
            state: "quota-failure-state".to_owned(),
            nonce: None,
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
            prompt: None,
            max_age: None,
            reauth_required: false,
            reauth_session_token_hash: None,
            owner_user_id: Some(user_id),
            session_token_hash: None,
        },
        None,
        None,
    )
    .await
    .expect_err("authorization code persistence failure");
    assert_eq!(result.status(), StatusCode::SERVICE_UNAVAILABLE);

    // take() 与 save() 共用一个已经损坏的存储，无法证明授权码没有落盘；此刻
    // 立即退款可能让同一授权在码实际存在的情况下二次消耗配额，所以实现选择
    // 保守等待：配额暂时占用，由 #341 的过期退款台账兜底。
    let immediately_after = state
        .oauth_quotas
        .snapshot(&client_id, limits)
        .await
        .expect("quota immediately after failed authorization");
    assert_eq!(immediately_after.daily_used, before.daily_used + 1);

    // 授权码 TTL 过后，退款 worker 把未兑换的 reservation 还回去。
    state
        .oauth_quotas
        .run_refund_worker_pass(state.clock.now() + time::Duration::seconds(360))
        .await
        .expect("run quota refund worker pass");
    let after = state
        .oauth_quotas
        .snapshot(&client_id, limits)
        .await
        .expect("quota after refund worker");
    assert_eq!(after.daily_used, before.daily_used);
    assert_eq!(after.monthly_used, before.monthly_used);

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

/// 建立一条浏览器会话并返回 `(cookie, csrf)`，供撤销授权等 SessionWrite 端点使用。
async fn test_session(state: &AppState, user_id: i64) -> (String, String) {
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("browser session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    (
        format!(
            "chenxing_session={}; chenxing_csrf={}",
            session.token, session.csrf_token
        ),
        session.csrf_token,
    )
}

/// 通过浏览器会话撤销对某个应用的授权（Issue #417 / #418 的入口）。
async fn revoke_authorized_app(router: &axum::Router, cookie: &str, csrf: &str, client_id: &str) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/authorized-apps/{client_id}"))
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .expect("revoke authorized app request"),
        )
        .await
        .expect("revoke authorized app response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

/// Issue #417：用户撤销授权后，TTL 内尚未使用的授权码必须 `invalid_grant`。
///
/// 授权码兑换此前没有 consent 门禁，撤销「断开应用」后仍可换出 AT + RT。
/// 修复后兑换在 CAS 消费授权码之前先过统一的授权闸门。
#[tokio::test]
async fn revoked_consent_rejects_unused_authorization_code_exchange() {
    let (state, database, key_directory) = test_state("oauth_flow").await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&router, "flow-admin-token").await;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(&client_id)
    .bind(serde_json::json!(["openid", "profile"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(&database)
    .await
    .expect("save consent");
    let code = AuthorizationCode::new_with_nonce(
        client_id.clone(),
        "https://disabled.example/callback".to_owned(),
        user_id.to_string(),
        vec!["openid".to_owned(), "profile".to_owned()],
        challenge,
        None,
        Some(bound_session_token(&state, user_id).await),
    )
    .with_issuer_generation(test_issuer(&state).generation());
    state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");

    let (cookie, csrf) = test_session(&state, user_id).await;
    revoke_authorized_app(&router, &cookie, &csrf, &client_id).await;

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
                .expect("revoked consent code exchange request"),
        )
        .await
        .expect("revoked consent code exchange response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["error"].as_str(),
        Some("invalid_grant"),
        "an unused code must not be exchangeable after consent revocation"
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

/// Issue #418：撤销应用授权必须销毁该 grant 下的 Refresh Token，而不是只写一条
/// consent 撤销等下次兑换被挡住。撤销后既有 refresh 立即 `invalid_grant`，审计
/// 记录凭据清理结果。
#[tokio::test]
async fn consent_revoke_destroys_refresh_tokens_and_audits_cleanup() {
    let (state, database, key_directory) = test_state("oauth_flow").await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&router, "flow-admin-token").await;
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(&client_id)
    .bind(serde_json::json!(["openid"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(&database)
    .await
    .expect("save consent");
    let refresh = RefreshToken::new(
        client_id.clone(),
        user_id.to_string(),
        vec!["openid".to_owned()],
    );
    state
        .refresh_tokens
        .save(&refresh)
        .await
        .expect("save refresh token");

    let (cookie, csrf) = test_session(&state, user_id).await;
    revoke_authorized_app(&router, &cookie, &csrf, &client_id).await;

    // 凭据被立即销毁：既有的 refresh 在撤销后立刻 invalid_grant，无需等自然过期。
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
                    "grant_type=refresh_token&refresh_token={}",
                    refresh.value
                )))
                .expect("revoked grant refresh request"),
        )
        .await
        .expect("revoked grant refresh response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["error"].as_str(),
        Some("invalid_grant"),
        "a refresh token must not outlive consent revocation"
    );

    // 审计记录凭据清理结果（验收项）。
    let (events, _total) = state
        .audit
        .query(Some("consent_revoke"), Some("oauth_consent"), 100, 0)
        .await
        .expect("query consent revoke audit events");
    let event = events
        .iter()
        .find(|event| event.resource_id.as_deref() == Some(client_id.as_str()))
        .expect("consent revoke audit event");
    assert_eq!(
        event
            .metadata
            .get("revoked_refresh_tokens")
            .and_then(|v| v.as_u64()),
        Some(1),
        "audit must record the number of destroyed refresh tokens"
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

/// Issue #421：Client 缩减注册 scope 后，refresh / UserInfo 不得再按旧 scope 集
/// 续签或返回 claim——只允许收窄后的集合。
#[tokio::test]
async fn shrinking_client_scopes_narrows_refresh_and_userinfo() {
    let (state, database, key_directory) = test_state("oauth_flow").await;
    let router = api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &database, "oauth_flow", &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&router, "flow-admin-token").await;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ];
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(&client_id)
    .bind(serde_json::json!(["openid", "profile", "email"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(&database)
    .await
    .expect("save consent");
    let code = AuthorizationCode::new_with_nonce(
        client_id.clone(),
        "https://disabled.example/callback".to_owned(),
        user_id.to_string(),
        scopes.clone(),
        challenge,
        None,
        Some(bound_session_token(&state, user_id).await),
    )
    .with_issuer_generation(test_issuer(&state).generation());
    state
        .authorization_codes
        .save(&code)
        .await
        .expect("save authorization code");
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let exchange = router
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
    assert_eq!(exchange.status(), StatusCode::OK);
    let exchange_body = json_body(exchange).await;
    let access_token = exchange_body["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();
    let refresh_value = exchange_body["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();

    // 管理员把 Client 注册 scope 从 [openid, profile, email] 缩减到 [openid]。
    let update = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/clients/{client_id}"))
                .header("authorization", "Bearer flow-admin-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": "Disabled User Client",
                        "redirect_uris": ["https://disabled.example/callback"],
                        "scopes": ["openid"],
                    })
                    .to_string(),
                ))
                .expect("client scope shrink request"),
        )
        .await
        .expect("client scope shrink response");
    assert_eq!(update.status(), StatusCode::NO_CONTENT);

    // refresh 显式请求已删除的 scope：不得再签发。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh_value}&scope=openid+profile"
                )))
                .expect("refresh with dropped scope request"),
        )
        .await
        .expect("refresh with dropped scope response");
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a dropped scope must not be re-issued on refresh"
    );

    // refresh 不带 scope：只签发收窄后的集合（openid）。
    let response = router
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
                .expect("narrowed refresh request"),
        )
        .await
        .expect("narrowed refresh response");
    assert_eq!(response.status(), StatusCode::OK);
    let narrowed = json_body(response).await;
    assert_eq!(
        narrowed["scope"].as_str(),
        Some("openid"),
        "refresh must be narrowed to the client's current registered scopes"
    );

    // UserInfo：不再注册的 scope 对应的 claim 不得再返回。
    let userinfo = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .expect("narrowed userinfo request"),
        )
        .await
        .expect("narrowed userinfo response");
    assert_eq!(userinfo.status(), StatusCode::OK);
    let claims = json_body(userinfo).await;
    assert_eq!(claims["sub"].as_str(), Some(user_id.to_string().as_str()));
    assert!(
        claims.get("email").is_none() && claims.get("name").is_none(),
        "UserInfo must not return claims for scopes removed from the client: {claims}"
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
