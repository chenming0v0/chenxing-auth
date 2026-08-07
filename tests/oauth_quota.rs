use chenxing_auth::oauth::quota::{OAuthQuotaStore, QuotaConsumeResult};
use chenxing_auth::plans::domain::AuthQuotaLimits;
use time::{Date, Month, OffsetDateTime, Time};
use uuid::Uuid;

#[test]
fn quota_store_can_be_constructed_from_redis_client() {
    let client = redis::Client::open("redis://127.0.0.1:6379").expect("redis URL");
    let _store = OAuthQuotaStore::new(client);
}

#[tokio::test]
async fn refund_is_idempotent_and_stays_with_the_consumed_period() {
    let store =
        OAuthQuotaStore::new(redis::Client::open("redis://127.0.0.1:6379").expect("redis URL"));
    let client_id = format!("quota-refund-{}", Uuid::new_v4().simple());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 10,
        monthly_auth_limit: Some(10),
    };
    let current_date = OffsetDateTime::now_utc().date();
    let next_month = match current_date.month() {
        Month::December => Date::from_calendar_date(current_date.year() + 1, Month::January, 1),
        month => Date::from_calendar_date(
            current_date.year(),
            Month::try_from(month as u8 + 1).expect("next month"),
            1,
        ),
    }
    .expect("next month date");
    let after_boundary =
        next_month.with_time(Time::MIDNIGHT).assume_utc() + time::Duration::seconds(1);
    let before_boundary = after_boundary - time::Duration::seconds(2);

    let first = store
        .consume_with_limits_and_reservation_at(&client_id, limits, before_boundary)
        .await
        .expect("first quota reservation");
    assert_eq!(first.result, QuotaConsumeResult::Allowed);
    let first_reservation = first.reservation().expect("first reservation");

    let second = store
        .consume_with_limits_and_reservation_at(&client_id, limits, after_boundary)
        .await
        .expect("second quota reservation");
    assert_eq!(second.result, QuotaConsumeResult::Allowed);
    let second_reservation = second.reservation().expect("second reservation");

    store
        .refund(&first_reservation)
        .await
        .expect("refund first reservation");
    store
        .refund(&first_reservation)
        .await
        .expect("repeat refund is harmless");

    let previous_period = store
        .snapshot_at(&client_id, Some(limits), before_boundary)
        .await
        .expect("previous period snapshot");
    assert_eq!(previous_period.daily_used, 0);
    assert_eq!(previous_period.monthly_used, 0);

    let current_period = store
        .snapshot_at(&client_id, Some(limits), after_boundary)
        .await
        .expect("current period snapshot");
    assert_eq!(current_period.daily_used, 1);
    assert_eq!(current_period.monthly_used, 1);

    store
        .refund(&second_reservation)
        .await
        .expect("refund second reservation");
    let empty_current_period = store
        .snapshot_at(&client_id, Some(limits), after_boundary)
        .await
        .expect("empty current period snapshot");
    assert_eq!(empty_current_period.daily_used, 0);
    assert_eq!(empty_current_period.monthly_used, 0);
}
