//! Entitlement aggregation and empty/read-only states without an effective plan.

use super::*;

#[tokio::test]
async fn entitlements_aggregate_usage_across_multiple_clients() {
    let env = test_state_from_template().await;
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

/// 权益端点描述状态，「没有生效套餐」是状态而不是错误：200 + `plan: null`。
#[tokio::test]
async fn entitlements_returns_empty_state_when_no_plan() {
    let env = test_state_from_template().await;
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
    let env = test_state_from_template().await;
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
