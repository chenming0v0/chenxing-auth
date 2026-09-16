//! Split from `flow.rs` (nested child module).

use super::*;

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
    chenxing_auth::sqlx::query(
        "UPDATE oauth_clients SET owner_user_id = $1, quota_exempt = false WHERE client_id = $2",
    )
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
