//! Missing-default-plan semantics: self-service gate closes, existing integrations keep working.

use super::*;

/// 取消唯一默认套餐后，自助接入闸门关闭（新建 Client 403），
/// 但**既有 Client 的授权路径必须继续可用** —— 闸门只关新增，不打死既有集成。
#[tokio::test]
async fn unsetting_the_last_default_plan_closes_self_service() {
    let env = test_state_from_template().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    // 闸门关闭前先建一个 Client，作为「既有集成」。
    let existing = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let existing_client_id = existing["client_id"]
        .as_str()
        .expect("existing client id")
        .to_owned();

    // 取消唯一默认套餐：现在是合法操作（旧语义是 409 default_plan_protected）。
    let (status, _) = update_plan(
        &router,
        env.default_plan_id,
        &format!("unset-{suffix}"),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let plans = list_plans(&router).await;
    let active_defaults = plans
        .as_array()
        .expect("plans array")
        .iter()
        .filter(|plan| plan["status"] == "active" && plan["is_default"] == true)
        .count();
    assert_eq!(active_defaults, 0);
    assert_eq!(active_default_plan_count(&env.database).await, 0);

    // 新增被拒。
    let refused = post_owned_client(&router, &cookie, &csrf, &format!("refused-{suffix}")).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(json(refused).await["code"], "self_service_disabled");

    // 既有 Client 的授权仍然成功：这是防止「只关新增」被悄悄改成
    // 「打死既有集成」的机器保障。
    let session_token = bound_session_token(&env.state, user_id).await;
    let session_hash = chenxing_auth::sessions::domain::session_token_hash(&session_token);
    let mut validated = validated_request(&existing_client_id, user_id);
    validated.session_token_hash = Some(session_hash);
    let result = issue_authorization_code_result(
        &env.state,
        test_issuer(&env.state).as_ref(),
        user_id.to_string(),
        validated,
        None,
        None,
    )
    .await
    .expect("existing client authorization must keep working without a default plan");
    assert!(matches!(result, AuthorizationCodeIssue::Redirect(_)));

    env.cleanup().await;
}

/// 没有任何套餐 → 自助接入闸门关闭。
#[tokio::test]
async fn no_default_plan_refuses_new_client_creation() {
    let env = test_state_from_template().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    clear_all_plans(&env.database).await;
    assert_eq!(active_default_plan_count(&env.database).await, 0);

    let response = post_owned_client(&router, &cookie, &csrf, &suffix).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json(response).await["code"], "self_service_disabled");

    env.cleanup().await;
}

/// 闸门只关新增：套餐清空后，既有用户 Client 的 authorize 和 token 兑换都要成功。
#[tokio::test]
async fn no_default_plan_keeps_existing_user_clients_working() {
    let env = test_state_from_template().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let client_secret = client["client_secret"]
        .as_str()
        .expect("client secret")
        .to_owned();

    clear_all_plans(&env.database).await;
    assert_eq!(active_default_plan_count(&env.database).await, 0);

    // 授权码兑换在 CAS 前校验 consent（Issue #417），`issue_authorization_code_result`
    // 直发路径不写 consent 行，补上以匹配生产 approve 流程。
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(&client_id)
    .bind(serde_json::json!(["openid", "profile"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(&env.database)
    .await
    .expect("save code exchange consent");

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let session_token = bound_session_token(&env.state, user_id).await;
    let session_hash = chenxing_auth::sessions::domain::session_token_hash(&session_token);
    let mut validated =
        validated_request_with_challenge(&client_id, user_id, &code_challenge_for(verifier));
    validated.session_token_hash = Some(session_hash);
    let issued = issue_authorization_code_result(
        &env.state,
        test_issuer(&env.state).as_ref(),
        user_id.to_string(),
        validated,
        None,
        None,
    )
    .await
    .expect("authorization must succeed without any plan");
    let AuthorizationCodeIssue::Redirect(redirect) = issued else {
        panic!("authorization without a plan must not be quota-limited");
    };
    let code = authorization_code_from_redirect(&redirect);

    let (status, token) =
        exchange_authorization_code(&router, &client_id, &client_secret, &code, verifier).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {token}");
    assert!(token["access_token"].as_str().is_some());
    assert!(token["refresh_token"].as_str().is_some());

    env.cleanup().await;
}

/// 管理端创建的 Client 会 stamp 到第一个未禁用 Owner；清掉套餐后授权/换令牌
/// 仍成功——没有生效套餐时跳过计量，不打死既有集成。
#[tokio::test]
async fn admin_owned_clients_are_unaffected_by_missing_default_plan() {
    let env = test_state_from_template().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;

    let client = create_admin_client(&router, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let client_secret = client["client_secret"]
        .as_str()
        .expect("client secret")
        .to_owned();
    let owner: Option<i64> = chenxing_auth::sqlx::query_scalar(
        "SELECT owner_user_id FROM oauth_clients WHERE client_id = $1",
    )
    .bind(&client_id)
    .fetch_one(&env.database)
    .await
    .expect("admin client owner");
    let first_owner: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT id FROM users WHERE role = 'owner' AND status <> 'disabled' ORDER BY id ASC LIMIT 1",
    )
    .fetch_one(&env.database)
    .await
    .expect("first active owner");
    assert_eq!(
        owner,
        Some(first_owner),
        "ADMIN_TOKEN created client belongs to the first active owner"
    );

    clear_all_plans(&env.database).await;

    // 授权码兑换在 CAS 前校验 consent（Issue #417），`issue_authorization_code_result`
    // 直发路径不写 consent 行，补上以匹配生产 approve 流程。
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(&client_id)
    .bind(serde_json::json!(["openid", "profile"]))
    .bind(time::OffsetDateTime::now_utc())
    .execute(&env.database)
    .await
    .expect("save code exchange consent");

    let verifier = "M25iVq8lYCr2Wl4nkPdz0oVYtIdYs1JRLmS3xN8sYAo";
    let session_token = bound_session_token(&env.state, user_id).await;
    let session_hash = chenxing_auth::sessions::domain::session_token_hash(&session_token);
    let mut validated =
        validated_request_with_challenge(&client_id, user_id, &code_challenge_for(verifier));
    validated.session_token_hash = Some(session_hash);
    let issued = issue_authorization_code_result(
        &env.state,
        test_issuer(&env.state).as_ref(),
        user_id.to_string(),
        validated,
        None,
        None,
    )
    .await
    .expect("admin client authorization must succeed without any plan");
    let AuthorizationCodeIssue::Redirect(redirect) = issued else {
        panic!("admin client authorization must not be quota-limited");
    };
    let code = authorization_code_from_redirect(&redirect);
    assert!(redirect.starts_with(REDIRECT_URI));

    let (status, token) =
        exchange_authorization_code(&router, &client_id, &client_secret, &code, verifier).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin client token exchange: {token}"
    );
    assert!(token["access_token"].as_str().is_some());

    env.cleanup().await;
}

/// 没有默认套餐时管理员仍能分配套餐。
/// 回归：`ensure_active_default` 曾让整个分配事务回滚。
#[tokio::test]
async fn assigning_a_plan_works_without_a_default_plan() {
    let env = test_state_from_template().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    clear_all_plans(&env.database).await;
    assert_eq!(active_default_plan_count(&env.database).await, 0);

    let plan = create_plan(&router, &suffix, plan_limits(1, 7, Some(70), None)).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(plan["is_default"], false);
    assert_eq!(active_default_plan_count(&env.database).await, 0);

    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT,
        "assigning a plan must not require an active default plan"
    );

    // 分配生效后该用户重新获得自助接入能力。
    let created = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    assert_eq!(created["quota"]["daily_limit"], 7);
    assert_eq!(created["quota"]["monthly_limit"], 70);

    let (status, body) = get_entitlements(&router, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["plan"]["code"], format!("plan-{suffix}"));

    env.cleanup().await;
}
