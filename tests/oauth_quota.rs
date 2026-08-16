use chenxing_auth::oauth::quota::{OAuthQuotaStore, QuotaConsumeResult, refund_due_unix_millis};
use chenxing_auth::plans::domain::AuthQuotaLimits;
use time::{Date, Duration, Month, OffsetDateTime, Time};
use uuid::Uuid;

const AUTHORIZATION_CODE_HANDLERS: &str =
    include_str!("../src/oauth/authorization_code_handlers.rs");
const TOKEN_USE_CASE_SUPPORT: &str = include_str!("../src/oauth/token_use_case_support.rs");
const QUOTA_REFUND: &str = include_str!("../src/oauth/quota_refund.rs");

#[test]
fn quota_store_can_be_constructed_from_redis_client() {
    let client = redis::Client::open("redis://127.0.0.1:6379").expect("redis URL");
    let _store = OAuthQuotaStore::new(client);
}

#[test]
fn authorization_code_compensation_skips_refund_when_removal_outcome_is_unknown() {
    let compensation = AUTHORIZATION_CODE_HANDLERS
        .split_once("async fn remove_authorization_code_after_failure")
        .map(|(_, source)| source)
        .and_then(|source| source.split_once("async fn refund_quota_if_consumed"))
        .map(|(source, _)| source)
        .expect("authorization-code compensation function");
    let (success_branch, error_branch) = compensation
        .split_once("Err(error_value) =>")
        .expect("explicit removal-error branch");

    assert!(
        compensation.contains("match state.authorization_codes.take(&code.value).await"),
        "compensation must branch on the authoritative Redis removal result"
    );
    assert!(
        success_branch.contains("Ok(_) => refund_quota_if_consumed"),
        "a definitive removal result may refund the reserved quota"
    );
    assert!(
        !error_branch.contains("refund_quota_if_consumed"),
        "an unknown removal outcome must fail closed without refunding quota"
    );
    assert!(error_branch.contains("quota refund skipped"));
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

#[test]
fn refund_due_millis_never_precedes_exact_expiry() {
    let exact_second = OffsetDateTime::UNIX_EPOCH + Duration::seconds(1_700_000_005);
    assert_eq!(refund_due_unix_millis(exact_second), 1_700_000_005_000);

    let nine_hundred_ms = exact_second + Duration::milliseconds(900);
    assert_eq!(refund_due_unix_millis(nine_hundred_ms), 1_700_000_005_900);

    let leftover_nanos = nine_hundred_ms + Duration::nanoseconds(1);
    assert_eq!(refund_due_unix_millis(leftover_nanos), 1_700_000_005_901);
}

#[test]
fn authorization_paths_schedule_refunds_from_exact_expiry() {
    assert!(
        AUTHORIZATION_CODE_HANDLERS.contains("schedule_refund(reservation, code.expires_at)"),
        "issue path must schedule from the exact expires_at"
    );
    assert!(
        !AUTHORIZATION_CODE_HANDLERS.contains("expires_at.unix_timestamp()"),
        "issue path must not truncate expiry to whole seconds"
    );
    assert!(
        TOKEN_USE_CASE_SUPPORT.contains("reschedule_refund(reservation_id, code.expires_at)"),
        "compensation must reschedule from the exact expires_at"
    );
    assert!(
        !TOKEN_USE_CASE_SUPPORT.contains("expires_at.unix_timestamp()"),
        "compensation must not truncate expiry to whole seconds"
    );
    assert!(
        QUOTA_REFUND.contains("refund_query_unix_millis(now)"),
        "worker query must use millisecond precision"
    );
}
