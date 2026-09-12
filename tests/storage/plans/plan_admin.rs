//! Admin plan lifecycle: archive/restore, default flag, code conflicts and assignment permissions.

use super::*;

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
