/// 集成测试：授权码必须绑定签发时的用户会话（#107）。
///
/// 核心回归：用户授权后立刻登出，该授权码在 5 分钟 TTL 内不得再兑换
/// access/refresh token；且**授权码不得被消费**——失败请求不能烧掉有效凭据
/// （AGENTS.md：「授权码必须在绑定、过期和 PKCE 检查通过后原子消费」）。
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/oauth_flow.rs"]
mod support;

use support::{
    create_test_client, ensure_owner_bootstrapped, json_body, register_test_user, session_cookie,
    test_state,
};

/// 完整的端到端流程：登录 → 授权 → 确认授权 → 撤销会话 → 兑换失败 → 授权码未消费。
///
/// 当 `session_id` 字段缺失（降级路径）时，Token 端点不做会话校验，此处单独
/// 用 `AuthorizationCode::new` 做该回归（见 `code.rs` 里的单元测试）。
#[tokio::test]
async fn authorization_code_rejected_after_session_revocation_and_code_not_consumed() {
    let (state, database, key_directory) = test_state().await;
    let router = chenxing_auth::api::router(state.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    ensure_owner_bootstrapped(&router, &suffix).await;
    let (user_id, _username, _email, _password) = register_test_user(&router, &suffix).await;
    let (client_id, client_secret) = create_test_client(&router, "flow-admin-token").await;

    // 直接用状态对象建立已保存的会话，拿到 Cookie。
    let mut session = chenxing_auth::sessions::domain::Session::new(
        user_id.to_string(),
        std::time::Duration::from_secs(3600),
    )
    .expect("session");
    state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist session");
    let cookie = session_cookie(&session);
    let csrf = session.csrf_token.clone();

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    // 授权端点 → 重定向到授权确认（首次访问无预授权）。
    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fdisabled.example%2Fcallback&response_type=code&scope=openid%20profile&state=session-bind-state&nonce=session-bind-nonce&code_challenge={challenge}&code_challenge_method=S256"
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
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "first authorization must redirect to consent"
    );
    let consent_location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("consent redirect location")
        .to_owned();
    let request_id = url::Url::parse(&format!("http://localhost{consent_location}"))
        .expect("consent URL")
        .query_pairs()
        .find(|(k, _)| k == "request_id")
        .map(|(_, v)| v.into_owned())
        .expect("request_id in consent location");

    // 授权确认（approve）→ 拿到授权码。
    let approve_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/oauth/authorize/requests/{request_id}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .expect("approve consent request"),
        )
        .await
        .expect("approve consent response");
    assert_eq!(approve_response.status(), StatusCode::OK);
    let decision = json_body(approve_response).await;
    let redirect_to = decision["redirect_to"]
        .as_str()
        .expect("redirect_to after approve");
    let code = url::Url::parse(redirect_to)
        .or_else(|_| {
            url::Url::parse("https://disabled.example").and_then(|base| base.join(redirect_to))
        })
        .expect("redirect URL")
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("authorization code in redirect");

    // 撤销会话（模拟用户登出）。
    state
        .sessions
        .revoke(&session.token)
        .await
        .expect("revoke session");

    // Token 端点兑换：会话已撤销，必须返回 invalid_grant。
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let exchange_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fdisabled.example%2Fcallback&code_verifier={verifier}"
                )))
                .expect("token request"),
        )
        .await
        .expect("token response");
    assert_ne!(
        exchange_response.status(),
        StatusCode::OK,
        "revoked session must prevent code exchange"
    );
    let body = json_body(exchange_response).await;
    assert_eq!(
        body["error"].as_str(),
        Some("invalid_grant"),
        "revoked session must return invalid_grant"
    );

    // 核心不变量：授权码不得被消费——同样的错误请求不能烧掉凭据。
    // 再次兑换返回的是同一个错误，而不是「code 不存在」。
    let still_exists = state
        .authorization_codes
        .find(&code)
        .await
        .expect("find authorization code after rejection")
        .is_some();
    assert!(
        still_exists,
        "rejected authorization code must remain in the store (code must not be consumed)"
    );

    // 第二次尝试必须返回同一种错误，而不是「code 不存在」。
    let retry_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("authorization", format!("Basic {basic}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fdisabled.example%2Fcallback&code_verifier={verifier}"
                )))
                .expect("retry token request"),
        )
        .await
        .expect("retry token response");
    assert_ne!(retry_response.status(), StatusCode::OK);
    let retry_body = json_body(retry_response).await;
    assert_eq!(
        retry_body["error"].as_str(),
        Some("invalid_grant"),
        "second attempt with revoked session must also return invalid_grant"
    );

    // 清理。
    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
        .bind(&client_id)
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
