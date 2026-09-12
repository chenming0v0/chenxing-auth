//! Authorization daily/monthly quota enforcement, failure refund and unlimited monthly plans.

use super::*;

#[tokio::test]
async fn assigned_plan_daily_and_monthly_limits_reject_authorizations() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let plan = create_plan(&router, &suffix, plan_limits(1, 2, Some(5), None)).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let session_token = bound_session_token(&env.state, user_id).await;
    let session_hash = chenxing_auth::sessions::domain::session_token_hash(&session_token);
    let mut validated = validated_request(&client_id, user_id);
    validated.session_token_hash = Some(session_hash);

    for _ in 0..2 {
        let result = issue_authorization_code_result(
            &env.state,
            test_issuer(&env.state).as_ref(),
            user_id.to_string(),
            validated.clone(),
            None,
            None,
        )
        .await
        .expect("authorization within daily limit");
        assert!(matches!(result, AuthorizationCodeIssue::Redirect(_)));
    }
    let result = issue_authorization_code_result(
        &env.state,
        test_issuer(&env.state).as_ref(),
        user_id.to_string(),
        validated,
        None,
        None,
    )
    .await
    .expect("authorization over daily limit");
    assert!(matches!(result, AuthorizationCodeIssue::QuotaExceeded));

    env.cleanup().await;
}

#[tokio::test]
async fn authorization_code_save_failure_refunds_consumed_quota() {
    let mut env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let plan = create_plan(&router, &suffix, plan_limits(1, 1, Some(5), None)).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let session_token = bound_session_token(&env.state, user_id).await;
    let session_hash = chenxing_auth::sessions::domain::session_token_hash(&session_token);
    let mut validated = validated_request(&client_id, user_id);
    validated.session_token_hash = Some(session_hash);

    let limits = Some(AuthQuotaLimits {
        daily_auth_limit: 1,
        monthly_auth_limit: Some(5),
    });
    let before = env
        .state
        .oauth_quotas
        .snapshot(&client_id, limits)
        .await
        .expect("quota before failed authorization");

    env.state.authorization_codes = AuthorizationCodeStore::new(
        redis::Client::open("redis://127.0.0.1:1").expect("unavailable Redis URL"),
    );
    let failed = issue_authorization_code_result(
        &env.state,
        test_issuer(&env.state).as_ref(),
        user_id.to_string(),
        validated.clone(),
        None,
        None,
    )
    .await;
    assert!(failed.is_err(), "authorization code persistence must fail");

    // take() 与 save() 共用一个已经损坏的存储，无法证明授权码没有落盘；此刻
    // 立即退款可能让同一授权在码实际存在的情况下二次消耗配额，所以实现选择
    // 保守等待：配额暂时占用，由 #341 的过期退款台账兜底。
    let immediately_after = env
        .state
        .oauth_quotas
        .snapshot(&client_id, limits)
        .await
        .expect("quota immediately after failed authorization");
    assert_eq!(immediately_after.daily_used, before.daily_used + 1);

    // 授权码 TTL 过后，退款 worker 把未兑换的 reservation 还回去。
    env.state
        .oauth_quotas
        .run_refund_worker_pass(env.state.clock.now() + time::Duration::seconds(360))
        .await
        .expect("run quota refund worker pass");
    let after_refund = env
        .state
        .oauth_quotas
        .snapshot(&client_id, limits)
        .await
        .expect("quota after refund worker");
    assert_eq!(after_refund.daily_used, before.daily_used);
    assert_eq!(after_refund.monthly_used, before.monthly_used);

    env.state.authorization_codes = AuthorizationCodeStore::new(env.state.redis.clone());
    let retry = issue_authorization_code_result(
        &env.state,
        test_issuer(&env.state).as_ref(),
        user_id.to_string(),
        validated,
        None,
        None,
    )
    .await
    .expect("retry after quota refund");
    assert!(matches!(retry, AuthorizationCodeIssue::Redirect(_)));

    let snapshot = env
        .state
        .oauth_quotas
        .snapshot(&client_id, limits)
        .await
        .expect("quota snapshot after successful retry");
    assert_eq!(snapshot.daily_limit, Some(1));
    assert_eq!(snapshot.daily_used, 1);
    assert_eq!(snapshot.monthly_used, 1);

    env.cleanup().await;
}

#[tokio::test]
async fn unlimited_monthly_plan_never_rejects_authorizations() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let plan = create_plan(&router, &suffix, plan_limits(1, 10, None, None)).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    assert_eq!(client["quota"]["daily_limit"], 10);
    assert!(client["quota"]["monthly_limit"].is_null());
    let session_token = bound_session_token(&env.state, user_id).await;
    let session_hash = chenxing_auth::sessions::domain::session_token_hash(&session_token);
    let mut validated = validated_request(&client_id, user_id);
    validated.session_token_hash = Some(session_hash);

    for _ in 0..6 {
        let result = issue_authorization_code_result(
            &env.state,
            test_issuer(&env.state).as_ref(),
            user_id.to_string(),
            validated.clone(),
            None,
            None,
        )
        .await
        .expect("monthly quota is unlimited");
        assert!(matches!(result, AuthorizationCodeIssue::Redirect(_)));
    }

    // 权益页把 monthly_auth 的 limit 渲染为 null（前端显示 ∞）。
    let (_, body) = get_entitlements(&router, &cookie).await;
    let monthly = body["entitlements"]
        .as_array()
        .expect("entitlements array")
        .iter()
        .find(|item| item["key"] == "monthly_auth")
        .expect("monthly_auth entitlement");
    assert!(monthly["limit"].is_null());
    assert_eq!(monthly["used"], 6);

    env.cleanup().await;
}
