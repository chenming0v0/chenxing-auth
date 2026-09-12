//! Plan-scoped client quota, entitlements snapshot and serialized concurrent creation.

use super::*;

fn service_client_input(label: &str) -> ClientRegistrationInput {
    ClientRegistrationInput {
        client_name: format!("Quota race {label}"),
        redirect_uris: vec![format!("https://{label}.example/callback")],
        scopes: vec!["openid".to_owned()],
        logo_uri: None,
        client_uri: None,
        description: None,
    }
}

async fn owned_client_count(database: &chenxing_auth::sqlx::PgPool, user_id: i64) -> i64 {
    chenxing_auth::sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients WHERE owner_user_id = $1")
        .bind(user_id)
        .fetch_one(database)
        .await
        .expect("owned client count")
}

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

/// Issue #479：事务外读到高配套餐后，管理员先完成降级，随后继续的创建必须
/// 在 repository 事务内重读低配套餐，不能拿旧数字越过配额。
#[tokio::test]
async fn client_creation_rechecks_quota_after_plan_downgrade_commits() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;
    let (cookie, csrf) = user_session(&env.state, user_id).await;

    let high_plan = create_plan(
        &router,
        &format!("high-{suffix}"),
        plan_limits(2, 10, Some(100), None),
    )
    .await;
    let low_plan = create_plan(
        &router,
        &format!("low-{suffix}"),
        plan_limits(1, 10, Some(100), None),
    )
    .await;
    let high_plan_id = high_plan["id"].as_i64().expect("high plan id");
    let low_plan_id = low_plan["id"].as_i64().expect("low plan id");
    assert_eq!(
        assign_plan(&router, user_id, high_plan_id, None).await,
        StatusCode::NO_CONTENT
    );
    create_owned_client(&router, &cookie, &csrf, &format!("existing-{suffix}")).await;

    let stale_plan_read = Arc::new(Barrier::new(2));
    let downgrade_committed = Arc::new(Barrier::new(2));
    let create = {
        let plans = env.state.plans.clone();
        let clients = env.state.clients.clone();
        let input = service_client_input(&format!("after-downgrade-{suffix}"));
        let stale_plan_read = Arc::clone(&stale_plan_read);
        let downgrade_committed = Arc::clone(&downgrade_committed);
        async move {
            let stale = plans
                .effective_plan_for_user(user_id)
                .await
                .expect("read old effective plan")
                .expect("assigned high plan");
            assert_eq!(stale.plan.id, high_plan_id);
            assert_eq!(stale.plan.oauth_clients_limit, 2);
            stale_plan_read.wait().await;
            downgrade_committed.wait().await;
            clients.register_for_user(user_id, input).await
        }
    };
    let downgrade = {
        let router = router.clone();
        let stale_plan_read = Arc::clone(&stale_plan_read);
        let downgrade_committed = Arc::clone(&downgrade_committed);
        async move {
            stale_plan_read.wait().await;
            assert_eq!(
                assign_plan(&router, user_id, low_plan_id, None).await,
                StatusCode::NO_CONTENT
            );
            downgrade_committed.wait().await;
        }
    };

    let (creation, ()) = tokio::join!(create, downgrade);
    assert!(matches!(creation, Err(ClientServiceError::QuotaExceeded)));
    assert_eq!(owned_client_count(&env.database, user_id).await, 1);

    env.cleanup().await;
}

/// 同一用户的 COUNT + INSERT 必须由用户行锁串行化；两个同时起跑的创建在
/// 限额为 1 时只能有一个成功，不能各自在空快照中都看到 0。
#[tokio::test]
async fn concurrent_client_creations_remain_serialized_by_user_lock() {
    let env = test_state().await;
    let router = env.router();
    let suffix = Uuid::new_v4().simple().to_string();
    bootstrap_owner(&router, &suffix).await;
    let user_id = register_user(&router, &suffix).await;

    let plan = create_plan(
        &router,
        &format!("serial-{suffix}"),
        plan_limits(1, 10, Some(100), None),
    )
    .await;
    let plan_id = plan["id"].as_i64().expect("serial plan id");
    assert_eq!(
        assign_plan(&router, user_id, plan_id, None).await,
        StatusCode::NO_CONTENT
    );

    let start = Arc::new(Barrier::new(2));
    let first = {
        let clients = env.state.clients.clone();
        let input = service_client_input(&format!("first-{suffix}"));
        let start = Arc::clone(&start);
        async move {
            start.wait().await;
            clients.register_for_user(user_id, input).await
        }
    };
    let second = {
        let clients = env.state.clients.clone();
        let input = service_client_input(&format!("second-{suffix}"));
        let start = Arc::clone(&start);
        async move {
            start.wait().await;
            clients.register_for_user(user_id, input).await
        }
    };

    let (first, second) = tokio::join!(first, second);
    let created =
        usize::from(matches!(&first, Ok(Some(_)))) + usize::from(matches!(&second, Ok(Some(_))));
    let exceeded = usize::from(matches!(&first, Err(ClientServiceError::QuotaExceeded)))
        + usize::from(matches!(&second, Err(ClientServiceError::QuotaExceeded)));
    assert_eq!(created, 1);
    assert_eq!(exceeded, 1);
    assert_eq!(owned_client_count(&env.database, user_id).await, 1);

    env.cleanup().await;
}
