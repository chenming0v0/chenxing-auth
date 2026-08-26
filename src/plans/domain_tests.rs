use super::{
    AuthQuotaLimits, BillingPeriod, MAX_DAILY_AUTH_LIMIT, MAX_MONTHLY_AUTH_LIMIT,
    MAX_OAUTH_CLIENTS_LIMIT, MAX_QPS, Plan, PlanError, PlanInput, unsigned_quota,
    validate_plan_input,
};
use time::OffsetDateTime;

fn input() -> PlanInput {
    PlanInput {
        code: "vip".to_owned(),
        name: "VIP".to_owned(),
        description: Some("适合重度接入方".to_owned()),
        oauth_clients_limit: 2,
        daily_auth_limit: 2_500,
        monthly_auth_limit: Some(50_000),
        max_qps: Some(35),
        is_default: false,
        price_points: 0,
        billing_period: BillingPeriod::OneTime,
    }
}

fn plan_with_auth_limits(daily: i64, monthly: Option<i64>) -> Plan {
    let now = OffsetDateTime::UNIX_EPOCH;
    Plan {
        id: 1,
        code: "test".to_owned(),
        name: "Test".to_owned(),
        description: None,
        oauth_clients_limit: 1,
        daily_auth_limit: daily,
        monthly_auth_limit: monthly,
        max_qps: None,
        is_default: false,
        status: "active".to_owned(),
        price_points: 0,
        billing_period: BillingPeriod::OneTime,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn auth_quota_limits_preserve_zero_and_unlimited_monthly_values() {
    assert_eq!(
        plan_with_auth_limits(0, None).auth_quota_limits(),
        AuthQuotaLimits {
            daily_auth_limit: 0,
            monthly_auth_limit: None,
        }
    );
    assert_eq!(
        plan_with_auth_limits(7, Some(11)).auth_quota_limits(),
        AuthQuotaLimits {
            daily_auth_limit: 7,
            monthly_auth_limit: Some(11),
        }
    );
}

#[test]
fn unsigned_quota_does_not_clamp_negatives_to_zero() {
    assert_eq!(unsigned_quota(0), 0);
    assert_eq!(
        unsigned_quota(MAX_DAILY_AUTH_LIMIT),
        MAX_DAILY_AUTH_LIMIT as u64
    );
    let exploded = std::panic::catch_unwind(|| unsigned_quota(-1));
    assert!(
        exploded.is_err(),
        "negative quotas must not become 0 (that would DoS authorizations)"
    );
}

#[test]
fn auth_quota_limits_refuse_to_clamp_negative_daily_to_zero() {
    let exploded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = plan_with_auth_limits(-1, None).auth_quota_limits();
    }));
    assert!(exploded.is_err());
}

#[test]
fn auth_quota_limits_refuse_to_clamp_negative_monthly_to_zero() {
    let exploded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = plan_with_auth_limits(1, Some(-1)).auth_quota_limits();
    }));
    assert!(exploded.is_err());
}

#[test]
fn plan_serializes_timestamps_as_rfc3339() {
    let value = serde_json::to_value(plan_with_auth_limits(7, Some(11))).expect("plan serializes");

    assert_eq!(value["created_at"], "1970-01-01T00:00:00Z");
    assert_eq!(value["updated_at"], "1970-01-01T00:00:00Z");
}

#[test]
fn accepts_valid_plan_input() {
    let validated = validate_plan_input(input()).expect("valid input");
    assert_eq!(validated.code, "vip");
    assert_eq!(validated.max_qps, Some(35));
}

#[test]
fn accepts_quota_boundaries() {
    let mut value = input();
    value.daily_auth_limit = 0;
    value.monthly_auth_limit = Some(0);
    value.max_qps = Some(1);
    validate_plan_input(value).expect("zero daily/monthly and 1 QPS are valid");

    let mut value = input();
    value.daily_auth_limit = MAX_DAILY_AUTH_LIMIT;
    value.monthly_auth_limit = Some(MAX_MONTHLY_AUTH_LIMIT);
    value.max_qps = Some(MAX_QPS);
    let validated = validate_plan_input(value).expect("upper bounds are inclusive");
    assert_eq!(validated.daily_auth_limit, MAX_DAILY_AUTH_LIMIT);
    assert_eq!(validated.monthly_auth_limit, Some(MAX_MONTHLY_AUTH_LIMIT));
    assert_eq!(validated.max_qps, Some(MAX_QPS));

    let mut value = input();
    value.monthly_auth_limit = None;
    value.max_qps = None;
    let validated = validate_plan_input(value).expect("null monthly/qps remain unlimited");
    assert_eq!(validated.monthly_auth_limit, None);
    assert_eq!(validated.max_qps, None);
}

#[test]
fn normalizes_code_to_lowercase_and_trims() {
    let mut value = input();
    value.code = "  VIP-Tier_2 ".to_owned();
    assert_eq!(
        validate_plan_input(value).expect("valid code").code,
        "vip-tier_2"
    );
}

#[test]
fn rejects_invalid_codes() {
    for code in ["", "含有中文", "has space", "UPPER CASE", &"x".repeat(65)] {
        let mut value = input();
        value.code = code.to_owned();
        assert_eq!(
            validate_plan_input(value),
            Err(PlanError::InvalidCode),
            "code: {code}"
        );
    }
}

#[test]
fn rejects_invalid_names_and_descriptions() {
    let mut value = input();
    value.name = "   ".to_owned();
    assert_eq!(validate_plan_input(value), Err(PlanError::InvalidName));

    let mut value = input();
    value.name = "x".repeat(129);
    assert_eq!(validate_plan_input(value), Err(PlanError::InvalidName));

    let mut value = input();
    value.description = Some("x".repeat(513));
    assert_eq!(
        validate_plan_input(value),
        Err(PlanError::InvalidDescription)
    );
}

#[test]
fn rejects_negative_limits_and_zero_qps() {
    let mut value = input();
    value.oauth_clients_limit = -1;
    assert_eq!(
        validate_plan_input(value),
        Err(PlanError::InvalidOauthClientsLimit)
    );

    // 超过上界的配额同样被拒绝（Issue #415）
    let mut value = input();
    value.oauth_clients_limit = MAX_OAUTH_CLIENTS_LIMIT + 1;
    assert_eq!(
        validate_plan_input(value),
        Err(PlanError::InvalidOauthClientsLimit)
    );

    let mut value = input();
    value.daily_auth_limit = -1;
    assert_eq!(
        validate_plan_input(value),
        Err(PlanError::InvalidDailyLimit)
    );

    let mut value = input();
    value.monthly_auth_limit = Some(-1);
    assert_eq!(
        validate_plan_input(value),
        Err(PlanError::InvalidMonthlyLimit)
    );

    let mut value = input();
    value.max_qps = Some(0);
    assert_eq!(validate_plan_input(value), Err(PlanError::InvalidMaxQps));

    let mut value = input();
    value.price_points = -1;
    assert_eq!(
        validate_plan_input(value),
        Err(PlanError::InvalidPricePoints)
    );
}

#[test]
fn rejects_quotas_above_business_bounds() {
    let mut value = input();
    value.daily_auth_limit = MAX_DAILY_AUTH_LIMIT + 1;
    assert_eq!(
        validate_plan_input(value),
        Err(PlanError::InvalidDailyLimit)
    );

    let mut value = input();
    value.monthly_auth_limit = Some(MAX_MONTHLY_AUTH_LIMIT + 1);
    assert_eq!(
        validate_plan_input(value),
        Err(PlanError::InvalidMonthlyLimit)
    );

    let mut value = input();
    value.max_qps = Some(MAX_QPS + 1);
    assert_eq!(validate_plan_input(value), Err(PlanError::InvalidMaxQps));
}

#[test]
fn plan_input_defaults_price_points_and_billing_period() {
    let input: PlanInput = serde_json::from_value(serde_json::json!({
        "code": "vip",
        "name": "VIP",
        "oauth_clients_limit": 2,
        "daily_auth_limit": 2500,
        "is_default": false
    }))
    .expect("plan input deserializes");
    assert_eq!(input.price_points, 0);
    assert_eq!(input.billing_period, BillingPeriod::OneTime);
}

#[test]
fn treats_blank_description_as_none() {
    let mut value = input();
    value.description = Some("   ".to_owned());
    assert_eq!(validate_plan_input(value).expect("valid").description, None);
}
