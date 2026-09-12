use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chenxing_auth::{
    api,
    oauth::{code::AuthorizationCode, refresh::RefreshToken},
};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

use crate::oauth_flow as support;

use support::{
    create_test_client, ensure_owner_bootstrapped, json_body, register_test_user, test_state,
};

use super::flow::{bound_session_token, test_issuer};

/// 拆分自 `flow.rs`：access-token 签发失败时 refresh grant 的可用性，以及
/// TOTP 重置撤销对既有 refresh token 的失效处理。
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
