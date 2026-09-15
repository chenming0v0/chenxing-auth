use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chenxing_auth::sessions::domain::Session;
use chenxing_auth::{
    api,
    oauth::{code::AuthorizationCode, refresh::RefreshToken},
    state::AppState,
};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

use crate::oauth_flow as support;

use support::{
    create_test_client, ensure_owner_bootstrapped, json_body, register_test_user, test_state,
};

use super::flow::{bound_session_token, test_issuer};

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
