use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chenxing_auth::{
    oauth::{
        handlers::{AuthorizationCodeIssue, issue_authorization_code_result},
        quota::QuotaConsumeResult,
        store::AuthorizationCodeStore,
    },
    plans::domain::{AuthQuotaLimits, MAX_DAILY_AUTH_LIMIT, MAX_MONTHLY_AUTH_LIMIT, MAX_QPS},
};
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;

#[path = "support/plans.rs"]
mod support;

use support::{
    ADMIN_TOKEN, DEFAULT_PLAN_CODE, REDIRECT_URI, active_default_plan_count, archive_plan,
    assign_plan, authorization_code_from_redirect, bootstrap_owner, clear_all_plans,
    code_challenge_for, create_admin_client, create_owned_client, create_plan,
    exchange_authorization_code, get_entitlements, json, list_owned_clients, list_plans,
    plan_limits, plan_status_and_default, post_owned_client, register_user, restore_plan,
    submit_plan, test_state, update_plan, user_session, validated_request,
    validated_request_with_challenge,
};

#[tokio::test]
async fn assigned_plan_controls_client_quota_and_entitlements() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let plan = create_plan(&router, &suffix, plan_limits(1, 5, Some(100), None)).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let (status, clients) = list_owned_clients(&router, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        clients["items"]
            .as_array()
            .expect("empty client items")
            .is_empty()
    );

    let (_, empty_entitlements) = get_entitlements(&router, &cookie).await;
    let empty_items = empty_entitlements["entitlements"]
        .as_array()
        .expect("empty entitlements items");
    let empty_by_key = |key: &str| {
        empty_items
            .iter()
            .find(|item| item["key"] == key)
            .unwrap_or_else(|| panic!("missing entitlement {key}"))
    };
    assert_eq!(empty_by_key("daily_auth")["used"], 0);
    assert_eq!(empty_by_key("daily_auth")["limit"], 5);
    assert_eq!(empty_by_key("monthly_auth")["used"], 0);
    assert_eq!(empty_by_key("monthly_auth")["limit"], 100);

    let first = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    assert_eq!(first["quota"]["daily_limit"], 5);
    assert_eq!(first["quota"]["daily_used"], 0);
    assert_eq!(first["quota"]["monthly_limit"], 100);
    assert_eq!(first["quota"]["monthly_used"], 0);
    let second = post_owned_client(&router, &cookie, &csrf, &format!("second-{suffix}")).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let error = json(second).await;
    assert_eq!(error["code"], "oauth_client_quota_exceeded");

    let (status, body) = get_entitlements(&router, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["plan"]["code"], format!("plan-{suffix}"));
    let entitlements = body["entitlements"].as_array().expect("entitlements array");
    let by_key = |key: &str| {
        entitlements
            .iter()
            .find(|item| item["key"] == key)
            .unwrap_or_else(|| panic!("missing entitlement {key}"))
    };
    assert_eq!(by_key("oauth_clients")["used"], 1);
    assert_eq!(by_key("oauth_clients")["limit"], 1);
    assert_eq!(by_key("daily_auth")["limit"], 5);
    assert_eq!(by_key("monthly_auth")["limit"], 100);

    let (_, clients) = list_owned_clients(&router, &cookie).await;
    assert_eq!(clients["items"][0]["quota"]["daily_limit"], 5);
    assert_eq!(clients["items"][0]["quota"]["monthly_limit"], 100);

    let _ = first["client_id"].as_str();
    env.cleanup().await;
}

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
    let validated = validated_request(&client_id, user_id);

    for _ in 0..2 {
        let result = issue_authorization_code_result(
            &env.state,
            user_id.to_string(),
            validated.clone(),
            None,
            None,
        )
        .await
        .expect("authorization within daily limit");
        assert!(matches!(result, AuthorizationCodeIssue::Redirect(_)));
    }
    let result =
        issue_authorization_code_result(&env.state, user_id.to_string(), validated, None, None)
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
    let validated = validated_request(&client_id, user_id);

    env.state.authorization_codes = AuthorizationCodeStore::new(
        redis::Client::open("redis://127.0.0.1:1").expect("unavailable Redis URL"),
    );
    let failed = issue_authorization_code_result(
        &env.state,
        user_id.to_string(),
        validated.clone(),
        None,
        None,
    )
    .await;
    assert!(failed.is_err(), "authorization code persistence must fail");

    let limits = Some(AuthQuotaLimits {
        daily_auth_limit: 1,
        monthly_auth_limit: Some(5),
    });
    let snapshot = env
        .state
        .oauth_quotas
        .snapshot(&client_id, limits)
        .await
        .expect("quota snapshot after refund");
    assert_eq!(snapshot.daily_limit, Some(1));
    assert_eq!(snapshot.daily_used, 0);
    assert_eq!(snapshot.monthly_used, 0);

    env.state.authorization_codes = AuthorizationCodeStore::new(env.state.redis.clone());
    let retry =
        issue_authorization_code_result(&env.state, user_id.to_string(), validated, None, None)
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
    let validated = validated_request(&client_id, user_id);

    for _ in 0..6 {
        let result = issue_authorization_code_result(
            &env.state,
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

#[tokio::test]
async fn qps_limiter_rejects_requests_over_the_plan_limit() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    // 用 1 QPS 做顺序断言：第一发进入业务校验返回 400，第二发必被滑动窗口拒绝。
    // 这比并发三连更稳，也更直接验证 token 路径真正调用了 plan-backed limiter。
    // 窗口由 `support::qps_window` 注入成 60s（生产仍是 1s），两发之间那次 19 MiB
    // Argon2 校验再慢也不会把第一发挤出窗口。
    let plan = create_plan(
        &router,
        &suffix,
        plan_limits(1, 1_000, Some(10_000), Some(1)),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let client_secret = client["client_secret"]
        .as_str()
        .expect("client secret")
        .to_owned();
    let basic_credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let token_request = || {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("authorization", format!("Basic {basic_credentials}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("grant_type=authorization_code"))
            .expect("token request")
    };

    let invalid_basic_credentials = STANDARD.encode(format!("{client_id}:wrong-secret"));
    let invalid = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(
                    "authorization",
                    format!("Basic {invalid_basic_credentials}"),
                )
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=authorization_code"))
                .expect("invalid credential request"),
        )
        .await
        .expect("invalid credential response");
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);

    let first = router
        .clone()
        .oneshot(token_request())
        .await
        .expect("first token response");
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);

    let second = router
        .clone()
        .oneshot(token_request())
        .await
        .expect("second token response");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json(second).await["error"], "temporarily_unavailable");

    env.cleanup().await;
}

#[tokio::test]
async fn entitlements_aggregate_usage_across_multiple_clients() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let plan = create_plan(&router, &suffix, plan_limits(2, 100, Some(1_000), None)).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let first = create_owned_client(&router, &cookie, &csrf, &format!("a-{suffix}")).await;
    let second = create_owned_client(&router, &cookie, &csrf, &format!("b-{suffix}")).await;
    let first_id = first["client_id"]
        .as_str()
        .expect("first client id")
        .to_owned();
    let second_id = second["client_id"]
        .as_str()
        .expect("second client id")
        .to_owned();

    let limits = AuthQuotaLimits {
        daily_auth_limit: 100,
        monthly_auth_limit: Some(1_000),
    };
    for _ in 0..2 {
        assert_eq!(
            env.state
                .oauth_quotas
                .consume_with_limits(&first_id, limits)
                .await
                .expect("first client quota"),
            QuotaConsumeResult::Allowed
        );
    }
    assert_eq!(
        env.state
            .oauth_quotas
            .consume_with_limits(&second_id, limits)
            .await
            .expect("second client quota"),
        QuotaConsumeResult::Allowed
    );

    let (status, body) = get_entitlements(&router, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let entitlements = body["entitlements"].as_array().expect("entitlements array");
    let by_key = |key: &str| {
        entitlements
            .iter()
            .find(|item| item["key"] == key)
            .unwrap_or_else(|| panic!("missing entitlement {key}"))
    };
    assert_eq!(by_key("oauth_clients")["used"], 2);
    assert_eq!(by_key("daily_auth")["used"], 3);
    assert_eq!(by_key("monthly_auth")["used"], 3);

    env.cleanup().await;
}

/// 归档默认套餐是合法操作：结果是「平台没有生效默认套餐」。
/// 同一条 UPDATE 顺手清掉 `is_default`，否则 `plans_default_must_be_active`
/// 会被违反。
#[tokio::test]
async fn admin_plan_archive_restore_and_default_clearing() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;

    let plan = create_plan(&router, &suffix, plan_limits(1, 5, None, None)).await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        archive_plan(&router, plan_id).await.status(),
        StatusCode::NO_CONTENT
    );

    // 归档后的套餐不能再分配给新用户。
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/plan"))
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "plan_id": plan_id, "expires_at": null }).to_string(),
                ))
                .expect("assign archived plan request"),
        )
        .await
        .expect("assign archived plan response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "plan_archived");

    assert_eq!(
        restore_plan(&router, plan_id).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    // 归档默认套餐：204，并且 `is_default` 被同一条 UPDATE 顺手清掉。
    assert_eq!(
        archive_plan(&router, env.default_plan_id).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        plan_status_and_default(&env.database, env.default_plan_id).await,
        ("archived".to_owned(), false),
        "archiving the default plan must also clear the default flag"
    );
    assert_eq!(active_default_plan_count(&env.database).await, 0);

    // 列表包含归档状态。
    let plans = list_plans(&router).await;
    let restored = plans
        .as_array()
        .expect("plans array")
        .iter()
        .find(|entry| entry["id"] == plan_id)
        .expect("created plan");
    assert_eq!(restored["status"], "active");
    assert_eq!(restored["assigned_users"], 1);

    env.cleanup().await;
}

/// 取消唯一默认套餐后，自助接入闸门关闭（新建 Client 403），
/// 但**既有 Client 的授权路径必须继续可用** —— 闸门只关新增，不打死既有集成。
#[tokio::test]
async fn unsetting_the_last_default_plan_closes_self_service() {
    let env = test_state().await;
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
    let result = issue_authorization_code_result(
        &env.state,
        user_id.to_string(),
        validated_request(&existing_client_id, user_id),
        None,
        None,
    )
    .await
    .expect("existing client authorization must keep working without a default plan");
    assert!(matches!(result, AuthorizationCodeIssue::Redirect(_)));

    env.cleanup().await;
}

#[tokio::test]
async fn archived_plan_cannot_become_default() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;

    let plan = create_plan(&router, &suffix, plan_limits(2, 2_500, Some(50_000), None)).await;
    let plan_id = plan["id"].as_i64().expect("archived plan id");
    assert_eq!(
        archive_plan(&router, plan_id).await.status(),
        StatusCode::NO_CONTENT
    );

    let (status, error) = update_plan(&router, plan_id, &format!("archived-{suffix}"), true).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["code"], "archived_plan_default");

    env.cleanup().await;
}

#[tokio::test]
async fn updating_plan_code_conflict_returns_409_business_error() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;

    let first = create_plan(
        &router,
        &format!("first-{suffix}"),
        plan_limits(2, 2_500, Some(50_000), None),
    )
    .await;
    let second = create_plan(
        &router,
        &format!("second-{suffix}"),
        plan_limits(2, 2_500, Some(50_000), None),
    )
    .await;

    let first_code = first["code"].as_str().expect("first plan code");
    let second_id = second["id"].as_i64().expect("second plan id");
    let (status, error) = update_plan(&router, second_id, first_code, false).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["code"], "plan_code_conflict");

    env.cleanup().await;
}

/// `plans_single_default_idx` + advisory lock 的不变式：并发把两个套餐设为默认，
/// 最终 active 默认套餐**至多一个**（新语义下 0 也合法，两个才是 bug）。
#[tokio::test]
async fn concurrent_default_updates_leave_at_most_one_active_default() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;

    let first = create_plan(
        &router,
        &format!("concurrent-a-{suffix}"),
        plan_limits(2, 2_500, Some(50_000), None),
    )
    .await;
    let second = create_plan(
        &router,
        &format!("concurrent-b-{suffix}"),
        plan_limits(2, 2_500, Some(50_000), None),
    )
    .await;
    let first_id = first["id"].as_i64().expect("first concurrent plan id");
    let second_id = second["id"].as_i64().expect("second concurrent plan id");

    let first_code = format!("default-a-{suffix}");
    let second_code = format!("default-b-{suffix}");
    let (first_update, second_update) = tokio::join!(
        update_plan(&router, first_id, &first_code, true),
        update_plan(&router, second_id, &second_code, true),
    );
    assert_eq!(first_update.0, StatusCode::OK);
    assert_eq!(second_update.0, StatusCode::OK);

    let plans = list_plans(&router).await;
    let defaults = plans
        .as_array()
        .expect("plans array")
        .iter()
        .filter(|plan| plan["status"] == "active" && plan["is_default"] == true)
        .count();
    assert_eq!(defaults, 1);
    assert_eq!(active_default_plan_count(&env.database).await, 1);

    // 收尾：把默认标记交回播种的套餐，验证新语义下这条路径依然通畅。
    let (status, _) = update_plan(&router, env.default_plan_id, DEFAULT_PLAN_CODE, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(active_default_plan_count(&env.database).await, 1);

    env.cleanup().await;
}

/// 没有任何套餐 → 自助接入闸门关闭。
#[tokio::test]
async fn no_default_plan_refuses_new_client_creation() {
    let env = test_state().await;
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
    let env = test_state().await;
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
    let issued = issue_authorization_code_result(
        &env.state,
        user_id.to_string(),
        validated_request_with_challenge(&client_id, user_id, &code_challenge_for(verifier)),
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

/// 权益端点描述状态，「没有生效套餐」是状态而不是错误：200 + `plan: null`。
#[tokio::test]
async fn entitlements_returns_empty_state_when_no_plan() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, _csrf) = user_session(&env.state, user_id).await;

    clear_all_plans(&env.database).await;

    let (status, body) = get_entitlements(&router, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["plan"].is_null(), "plan must serialize as null");
    assert_eq!(
        body["entitlements"].as_array().expect("entitlements array"),
        &Vec::<Value>::new()
    );

    env.cleanup().await;
}

/// 读路径不设闸门：没有套餐时照常列出既有 Client，配额上限留空、用量照报。
#[tokio::test]
async fn listing_clients_without_plan_reports_null_limits() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();

    clear_all_plans(&env.database).await;

    let (status, clients) = list_owned_clients(&router, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let item = clients["items"]
        .as_array()
        .expect("client items")
        .iter()
        .find(|item| item["client_id"] == client_id.as_str())
        .expect("existing client stays listed without a plan");
    assert!(
        item["quota"]["daily_limit"].is_null(),
        "daily_limit must be null without a plan"
    );
    assert!(
        item["quota"]["monthly_limit"].is_null(),
        "monthly_limit must be null without a plan"
    );
    assert_eq!(item["quota"]["daily_used"], 0);
    assert_eq!(item["quota"]["monthly_used"], 0);

    env.cleanup().await;
}

/// 管理端创建的 Client（`owner_user_id IS NULL`）不参与套餐计量，
/// 缺少默认套餐时 authorize / token 全程正常。
#[tokio::test]
async fn admin_owned_clients_are_unaffected_by_missing_default_plan() {
    let env = test_state().await;
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
    assert!(owner.is_none(), "admin client must not have an owner");

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
    let issued = issue_authorization_code_result(
        &env.state,
        user_id.to_string(),
        validated_request_with_challenge(&client_id, user_id, &code_challenge_for(verifier)),
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
    let env = test_state().await;
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

/// Issue #280：给 Owner 分配套餐要求 `ManageRoles`，但门槛充足时必须照常生效。
///
/// `authorization_audit` 守拒绝一侧（只有 `ManageUsers` 的 Admin 拿 403），
/// 这里守放行一侧：抬档不能把「Owner 的套餐永远改不动」当成修复结果。
#[tokio::test]
async fn assigning_a_plan_to_an_owner_succeeds_with_role_management_permission() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let owner_id: i64 =
        chenxing_auth::sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(format!("plan-owner-{suffix}"))
            .fetch_one(&env.database)
            .await
            .expect("bootstrapped owner id");

    let plan = create_plan(&router, &suffix, plan_limits(3, 9, Some(90), None)).await;
    let plan_id = plan["id"].as_i64().expect("plan id");

    // ADMIN_TOKEN 是系统令牌，拥有全部权限，包含 ManageRoles。
    assert_eq!(
        assign_plan(&router, owner_id, plan_id, None).await,
        StatusCode::NO_CONTENT,
        "sufficient permission must still be able to assign a plan to an owner"
    );
    let assigned: Option<i64> =
        chenxing_auth::sqlx::query_scalar("SELECT plan_id FROM users WHERE id = $1")
            .bind(owner_id)
            .fetch_one(&env.database)
            .await
            .expect("owner plan id");
    assert_eq!(assigned, Some(plan_id));

    env.cleanup().await;
}

/// 无生效套餐时 `enforce_qps` 里的 `effective?.plan.max_qps?` early-return
/// 路径的专项覆盖。
///
/// 这条路径与 `no_default_plan_keeps_existing_user_clients_working`（authorize 路径）
/// 守同一条不变式，但在 **token 路径**上：「闸门只关新增，不打死既有集成」。
/// 如果有人把那个 `?` 改成 `unwrap_or(0)` 或返回 503，authorize 那条测试抓不到，
/// 这条测试会抓到。
#[tokio::test]
async fn no_plan_skips_plan_qps_limiting_for_existing_clients() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    // Step 1: 创建 max_qps=1 的套餐并分配给用户。
    let plan = create_plan(
        &router,
        &suffix,
        plan_limits(1, 1_000, Some(10_000), Some(1)),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    // Step 2: 建一个 user client，记录凭据。
    let client = create_owned_client(&router, &cookie, &csrf, &suffix).await;
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let client_secret = client["client_secret"]
        .as_str()
        .expect("client secret")
        .to_owned();
    let basic_credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));

    let token_request = || {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("authorization", format!("Basic {basic_credentials}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("grant_type=authorization_code"))
            .expect("token request")
    };

    // Step 3: 先证明套餐下 QPS 闸门是生效的。
    // 第一发：凭据正确、套餐 QPS 允许，进入业务校验 → 400 (code 缺失)。
    // 第二发：同一个滑动窗口内第二次 → 429。
    // 窗口由 `support::qps_window` 注入成 60s（生产仍是 1s），因此两发必然落在同一
    // 窗口内，不再取决于 token 路径上那次 19 MiB Argon2 校验跑得有多快。
    // 这一步是关键：如果套餐 QPS 本来就不生效，第 5 步的「通过」就是假绿。
    let first = router
        .clone()
        .oneshot(token_request())
        .await
        .expect("first token response");
    assert_eq!(
        first.status(),
        StatusCode::BAD_REQUEST,
        "first request under plan must reach business logic (400 = plan QPS allowed)"
    );

    let second = router
        .clone()
        .oneshot(token_request())
        .await
        .expect("second token response under plan");
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "second request in the same window must be rejected by plan QPS (429)"
    );

    // Step 4: 清空所有套餐，模拟「平台无生效套餐」场景。
    clear_all_plans(&env.database).await;

    // Step 5: 连打多发确认按套餐 QPS 已跳过，不再出现 429 或 503。
    // 不 sleep：60s 窗口让第 3 步写入的条目**必然**还活着（以前只是「可能」），
    // 所以如果有人把 `?` 改成 `unwrap_or(0)` 导致限流仍然生效，第一发就会 429
    // 并立即失败。窗口注入把这条突变检测从概率性变成确定性。
    for i in 0..3_u32 {
        let resp = router
            .clone()
            .oneshot(token_request())
            .await
            .expect("post-clear token response");
        let status = resp.status();
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "request {i} after clearing plans must NOT be plan-QPS limited (429)"
        );
        assert_ne!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "request {i} after clearing plans must NOT return 503"
        );
        // 应当仍然进入业务校验并因缺少 code 返回 400。
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "request {i} after clearing plans must reach business logic (400)"
        );
    }

    // Step 6: 安全边界断言 —— 无套餐不等于全部限流失效。
    // 按源 IP 的 QPS 滑动窗口（`enforce_source_qps`）独立于套餐，
    // 清套餐后它必须仍然可以触发，防止有人误改成「无套餐 = 完全放行」。
    //
    // 用唯一 IP 的 ConnectInfo 通过 HTTP 路径真实调用 enforce_source_qps，
    // 预先饱和窗口后发起 HTTP 请求，验证 token_inner 仍然调用 enforce_source_qps。
    // 如果有人删掉了 enforce_source_qps 调用，此请求会进入业务逻辑返回 400，测试失败。
    // `chenxing:qps:source:{ip}` 是全局 Redis key，不受 schema 隔离保护。旧写法把
    // 整个 suffix 折叠进 203.0.113.0/24 的 254 个槽位，既丢掉测试身份也会在并发或
    // 重复运行时踩到别人的窗口。改用 IPv6 文档前缀 2001:db8::/32（RFC 3849）拼上本
    // 测试 Uuid 的低 96 位：地址与这次运行一一对应，冲突概率可以忽略。
    let uuid_tail = &suffix[suffix.len() - 24..];
    let groups: Vec<&str> = (0..6).map(|i| &uuid_tail[i * 4..i * 4 + 4]).collect();
    let fake_ip: IpAddr = format!("2001:db8:{}", groups.join(":"))
        .parse()
        .expect("valid IPv6 test address");
    // 限流 key 用 `IpAddr::to_string()` 的规范形式，必须和 handler 侧
    // （`api::source_ip` → `resolve_client_ip`）算出的字符串逐字节一致。
    let fake_ip_str = fake_ip.to_string();

    // 预先饱和该 IP 的源 QPS 窗口（默认限制 30）。
    let source_qps_limit = env.state.config.security_limits.unauthenticated_source_qps;
    for _ in 0..source_qps_limit {
        env.state
            .qps
            .allow_source(&fake_ip_str, source_qps_limit)
            .await
            .expect("pre-saturate source window");
    }

    // 现在用该 IP 发起 HTTP 请求，handler 会调用 enforce_source_qps 发现窗口已满 → 429。
    let saturated_request = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("authorization", format!("Basic {basic_credentials}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .extension(ConnectInfo(SocketAddr::new(fake_ip, 12345)))
        .body(Body::from("grant_type=authorization_code"))
        .expect("source-ip-saturated token request");

    let source_limited = router
        .clone()
        .oneshot(saturated_request)
        .await
        .expect("source-limited response");
    assert_eq!(
        source_limited.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "enforce_source_qps must still trigger (429) after clearing plans"
    );

    env.cleanup().await;
}

#[tokio::test]
async fn admin_api_accepts_quota_boundaries_and_rejects_values_outside_them() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;

    let created = create_plan(
        &router,
        &format!("bound-{suffix}"),
        plan_limits(
            1,
            MAX_DAILY_AUTH_LIMIT,
            Some(MAX_MONTHLY_AUTH_LIMIT),
            Some(i64::from(MAX_QPS)),
        ),
    )
    .await;
    assert_eq!(created["daily_auth_limit"], MAX_DAILY_AUTH_LIMIT);
    assert_eq!(created["monthly_auth_limit"], MAX_MONTHLY_AUTH_LIMIT);
    assert_eq!(created["max_qps"], MAX_QPS);

    let (status, error) = submit_plan(
        &router,
        &format!("over-daily-{suffix}"),
        plan_limits(1, MAX_DAILY_AUTH_LIMIT + 1, Some(5), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "invalid_plan");

    let (status, error) = submit_plan(
        &router,
        &format!("over-monthly-{suffix}"),
        plan_limits(1, 10, Some(MAX_MONTHLY_AUTH_LIMIT + 1), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "invalid_plan");

    let (status, error) = submit_plan(
        &router,
        &format!("over-qps-{suffix}"),
        plan_limits(1, 10, Some(20), Some(i64::from(MAX_QPS) + 1)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "invalid_plan");

    let (status, error) = submit_plan(
        &router,
        &format!("neg-daily-{suffix}"),
        plan_limits(1, -1, Some(5), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "invalid_plan");

    env.cleanup().await;
}

fn is_check_violation(error: &chenxing_auth::sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23514")
}

async fn insert_plan_bypassing_service(
    database: &chenxing_auth::sqlx::PgPool,
    code: &str,
    daily: i64,
    monthly: Option<i64>,
    max_qps: Option<i32>,
) -> Result<i64, chenxing_auth::sqlx::Error> {
    chenxing_auth::sqlx::query_scalar(
        "INSERT INTO plans (code, name, oauth_clients_limit, daily_auth_limit,
                            monthly_auth_limit, max_qps, status)
         VALUES ($1, $1, 1, $2, $3, $4, 'active')
         RETURNING id",
    )
    .bind(code)
    .bind(daily)
    .bind(monthly)
    .bind(max_qps)
    .fetch_one(database)
    .await
}

/// 绕过服务层的直接写入必须被数据库 CHECK 拦住，不能再靠读侧 `.max(0)` 把
/// 负数伪装成「配额为 0」。
#[tokio::test]
async fn database_check_rejects_quota_writes_that_bypass_the_service() {
    let env = test_state().await;
    let suffix = Uuid::new_v4().simple().to_string();

    let accepted = insert_plan_bypassing_service(
        &env.database,
        &format!("sql-ok-{suffix}"),
        MAX_DAILY_AUTH_LIMIT,
        Some(MAX_MONTHLY_AUTH_LIMIT),
        Some(MAX_QPS),
    )
    .await
    .expect("boundary values must be accepted by CHECK");
    assert!(accepted > 0);

    let unlimited =
        insert_plan_bypassing_service(&env.database, &format!("sql-null-{suffix}"), 0, None, None)
            .await
            .expect("zero daily and null monthly/qps remain valid");
    assert!(unlimited > 0);

    for (label, daily, monthly, max_qps) in [
        ("neg-daily", -1, Some(5), None),
        ("over-daily", MAX_DAILY_AUTH_LIMIT + 1, Some(5), None),
        ("neg-monthly", 10, Some(-1), None),
        ("over-monthly", 10, Some(MAX_MONTHLY_AUTH_LIMIT + 1), None),
        ("zero-qps", 10, Some(20), Some(0)),
        ("neg-qps", 10, Some(20), Some(-3)),
        ("over-qps", 10, Some(20), Some(MAX_QPS + 1)),
    ] {
        let error = insert_plan_bypassing_service(
            &env.database,
            &format!("sql-{label}-{suffix}"),
            daily,
            monthly,
            max_qps,
        )
        .await
        .expect_err(label);
        assert!(
            is_check_violation(&error),
            "{label} must hit CHECK 23514, got {error}"
        );
    }

    env.cleanup().await;
}
