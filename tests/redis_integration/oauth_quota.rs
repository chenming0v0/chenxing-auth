use chenxing_auth::{
    oauth::quota::{OAuthQuotaStore, QuotaConsumeResult},
    plans::domain::AuthQuotaLimits,
};
use uuid::Uuid;

fn store() -> OAuthQuotaStore {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    OAuthQuotaStore::new(redis::Client::open(url).expect("Redis URL"))
}

#[tokio::test]
async fn custom_limits_reject_daily_and_monthly_overages() {
    let store = store();
    let limits = AuthQuotaLimits {
        daily_auth_limit: 2,
        monthly_auth_limit: Some(10),
    };
    let daily_client = format!("quota-daily-{}", Uuid::new_v4().simple());
    assert_eq!(
        store
            .consume_with_limits(&daily_client, limits)
            .await
            .expect("first quota use"),
        QuotaConsumeResult::Allowed
    );
    assert_eq!(
        store
            .consume_with_limits(&daily_client, limits)
            .await
            .expect("second quota use"),
        QuotaConsumeResult::Allowed
    );
    assert_eq!(
        store
            .consume_with_limits(&daily_client, limits)
            .await
            .expect("daily quota rejection"),
        QuotaConsumeResult::DailyExceeded
    );

    let monthly_client = format!("quota-monthly-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 10,
        monthly_auth_limit: Some(2),
    };
    assert_eq!(
        store
            .consume_with_limits(&monthly_client, limits)
            .await
            .expect("first monthly use"),
        QuotaConsumeResult::Allowed
    );
    assert_eq!(
        store
            .consume_with_limits(&monthly_client, limits)
            .await
            .expect("second monthly use"),
        QuotaConsumeResult::Allowed
    );
    assert_eq!(
        store
            .consume_with_limits(&monthly_client, limits)
            .await
            .expect("monthly quota rejection"),
        QuotaConsumeResult::MonthlyExceeded
    );
}

#[tokio::test]
async fn null_monthly_limit_never_rejects_monthly() {
    let store = store();
    let client_id = format!("quota-unlimited-monthly-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 10,
        monthly_auth_limit: None,
    };
    for _ in 0..5 {
        assert_eq!(
            store
                .consume_with_limits(&client_id, limits)
                .await
                .expect("monthly use is unlimited"),
            QuotaConsumeResult::Allowed
        );
    }
}

#[tokio::test]
async fn concurrent_consumers_cannot_cross_daily_limit() {
    let store = store();
    let client_id = format!("quota-concurrent-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 2,
        monthly_auth_limit: Some(10),
    };
    let (first, second, third) = tokio::join!(
        store.consume_with_limits(&client_id, limits),
        store.consume_with_limits(&client_id, limits),
        store.consume_with_limits(&client_id, limits),
    );
    let results = [
        first.expect("first"),
        second.expect("second"),
        third.expect("third"),
    ];
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == QuotaConsumeResult::Allowed)
            .count(),
        2
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == QuotaConsumeResult::DailyExceeded)
            .count(),
        1
    );
}

#[tokio::test]
async fn empty_snapshot_uses_supplied_limits_and_zero_usage() {
    let store = store();
    let snapshot = store
        .snapshot(
            &format!("quota-empty-{}", Uuid::new_v4().simple()),
            Some(AuthQuotaLimits {
                daily_auth_limit: 7,
                monthly_auth_limit: Some(11),
            }),
        )
        .await
        .expect("empty quota snapshot");
    assert_eq!(snapshot.daily_limit, Some(7));
    assert_eq!(snapshot.daily_used, 0);
    assert_eq!(snapshot.monthly_limit, Some(11));
    assert_eq!(snapshot.monthly_used, 0);
}

#[tokio::test]
async fn snapshot_preserves_unlimited_monthly_limit_and_usage() {
    let store = store();
    let client_id = format!("quota-snapshot-unlimited-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 3,
        monthly_auth_limit: None,
    };
    assert_eq!(
        store
            .consume_with_limits(&client_id, limits)
            .await
            .expect("quota use"),
        QuotaConsumeResult::Allowed
    );
    let snapshot = store
        .snapshot(&client_id, Some(limits))
        .await
        .expect("snapshot");
    assert_eq!(snapshot.daily_limit, Some(3));
    assert_eq!(snapshot.daily_used, 1);
    assert_eq!(snapshot.monthly_limit, None);
    assert_eq!(snapshot.monthly_used, 1);
}

#[tokio::test]
async fn snapshot_without_plan_reports_usage_without_limits() {
    let store = store();
    let client_id = format!("quota-no-plan-{}", Uuid::new_v4().simple());
    assert_eq!(
        store
            .consume_with_limits(
                &client_id,
                AuthQuotaLimits {
                    daily_auth_limit: 5,
                    monthly_auth_limit: None,
                },
            )
            .await
            .expect("quota use"),
        QuotaConsumeResult::Allowed
    );
    let snapshot = store.snapshot(&client_id, None).await.expect("snapshot");
    assert_eq!(snapshot.daily_limit, None);
    assert_eq!(snapshot.monthly_limit, None);
    assert_eq!(snapshot.daily_used, 1);
    assert_eq!(snapshot.monthly_used, 1);
}

#[tokio::test]
async fn zero_daily_limit_rejects_at_empty_boundary() {
    let store = store();
    let result = store
        .consume_with_limits(
            &format!("quota-zero-{}", Uuid::new_v4().simple()),
            AuthQuotaLimits {
                daily_auth_limit: 0,
                monthly_auth_limit: Some(1),
            },
        )
        .await
        .expect("zero quota response");
    assert_eq!(result, QuotaConsumeResult::DailyExceeded);
}

#[tokio::test]
async fn redis_errors_are_returned_to_callers() {
    let store =
        OAuthQuotaStore::new(redis::Client::open("redis://127.0.0.1:1").expect("Redis URL"));
    let result = store
        .snapshot(
            "quota-error",
            Some(AuthQuotaLimits {
                daily_auth_limit: 1,
                monthly_auth_limit: Some(1),
            }),
        )
        .await;
    assert!(result.is_err());
}
