//! Quota boundary validation through the admin API and database CHECK constraints.

use super::*;

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

#[tokio::test]
async fn admin_api_accepts_quota_boundaries_and_rejects_values_outside_them() {
    let env = test_state_from_template().await;
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

/// 绕过服务层的直接写入必须被数据库 CHECK 拦住，不能再靠读侧 `.max(0)` 把
/// 负数伪装成「配额为 0」。
#[tokio::test]
async fn database_check_rejects_quota_writes_that_bypass_the_service() {
    let env = test_state_from_template().await;
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
