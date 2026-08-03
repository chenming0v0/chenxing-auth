use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

/// 套餐的持久化模型。`monthly_auth_limit` / `max_qps` 为 `NULL` 表示无限 / 不限。
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub id: i64,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub oauth_clients_limit: i32,
    pub daily_auth_limit: i64,
    pub monthly_auth_limit: Option<i64>,
    pub max_qps: Option<i32>,
    pub is_default: bool,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// OAuth daily/monthly authorization limits used by the quota store.
///
/// The database model keeps the daily limit non-null and uses `NULL` only for
/// an unlimited monthly limit. Keeping that distinction in a named value
/// avoids accidentally swapping the two dimensions at call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthQuotaLimits {
    pub daily_auth_limit: u64,
    pub monthly_auth_limit: Option<u64>,
}

impl Plan {
    pub fn auth_quota_limits(&self) -> AuthQuotaLimits {
        AuthQuotaLimits {
            daily_auth_limit: self.daily_auth_limit.max(0) as u64,
            monthly_auth_limit: self.monthly_auth_limit.map(|limit| limit.max(0) as u64),
        }
    }
}

/// 管理员创建 / 更新套餐时提交的原始输入。
#[derive(Debug, Deserialize)]
pub struct PlanInput {
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub oauth_clients_limit: i32,
    pub daily_auth_limit: i64,
    pub monthly_auth_limit: Option<i64>,
    pub max_qps: Option<i32>,
    pub is_default: bool,
}

/// 通过校验后的套餐输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPlanInput {
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub oauth_clients_limit: i32,
    pub daily_auth_limit: i64,
    pub monthly_auth_limit: Option<i64>,
    pub max_qps: Option<i32>,
    pub is_default: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("plan code must be 1-64 lowercase letters, digits, underscores or hyphens")]
    InvalidCode,
    #[error("plan name is required and must be at most 128 characters")]
    InvalidName,
    #[error("plan description must be at most 512 characters")]
    InvalidDescription,
    #[error("OAuth clients limit must not be negative")]
    InvalidOauthClientsLimit,
    #[error("daily authorization limit must not be negative")]
    InvalidDailyLimit,
    #[error("monthly authorization limit must not be negative")]
    InvalidMonthlyLimit,
    #[error("max QPS must be at least 1, or null for unlimited")]
    InvalidMaxQps,
    #[error("plan expiration must be in the future")]
    ExpiryInPast,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanMutationError {
    #[error("the active default plan cannot be unset")]
    DefaultPlanProtected,
    #[error("archived plans cannot be default")]
    ArchivedPlanCannotBeDefault,
    #[error("archived plans cannot be assigned to users")]
    PlanArchived,
}

pub fn validate_plan_update(
    plan: &Plan,
    input: &ValidatedPlanInput,
) -> Result<(), PlanMutationError> {
    if input.is_default && plan.status != "active" {
        return Err(PlanMutationError::ArchivedPlanCannotBeDefault);
    }
    if plan.status == "active" && plan.is_default && !input.is_default {
        return Err(PlanMutationError::DefaultPlanProtected);
    }
    Ok(())
}

pub fn validate_plan_archive(plan: &Plan) -> Result<(), PlanMutationError> {
    if plan.is_default {
        return Err(PlanMutationError::DefaultPlanProtected);
    }
    Ok(())
}

pub fn validate_plan_restore(plan: &Plan) -> Result<(), PlanMutationError> {
    if plan.status == "archived" && plan.is_default {
        return Err(PlanMutationError::ArchivedPlanCannotBeDefault);
    }
    Ok(())
}

pub fn validate_plan_assignment(plan: &Plan) -> Result<(), PlanMutationError> {
    if plan.status != "active" {
        return Err(PlanMutationError::PlanArchived);
    }
    Ok(())
}

pub fn validate_plan_input(input: PlanInput) -> Result<ValidatedPlanInput, PlanError> {
    let code = input.code.trim().to_ascii_lowercase();
    if code.is_empty()
        || code.chars().count() > 64
        || !code.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '_'
                || character == '-'
        })
    {
        return Err(PlanError::InvalidCode);
    }
    let name = input.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 128 {
        return Err(PlanError::InvalidName);
    }
    let description = input
        .description
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if description
        .as_ref()
        .is_some_and(|value| value.chars().count() > 512)
    {
        return Err(PlanError::InvalidDescription);
    }
    if input.oauth_clients_limit < 0 {
        return Err(PlanError::InvalidOauthClientsLimit);
    }
    if input.daily_auth_limit < 0 {
        return Err(PlanError::InvalidDailyLimit);
    }
    if input.monthly_auth_limit.is_some_and(|limit| limit < 0) {
        return Err(PlanError::InvalidMonthlyLimit);
    }
    // `max_qps` 为 `NULL` 表示不限并发；显式 0 没有意义且会拒绝所有请求。
    if input.max_qps.is_some_and(|qps| qps < 1) {
        return Err(PlanError::InvalidMaxQps);
    }
    Ok(ValidatedPlanInput {
        code,
        name,
        description,
        oauth_clients_limit: input.oauth_clients_limit,
        daily_auth_limit: input.daily_auth_limit,
        monthly_auth_limit: input.monthly_auth_limit,
        max_qps: input.max_qps,
        is_default: input.is_default,
    })
}

#[cfg(test)]
mod tests {
    use super::{AuthQuotaLimits, Plan, PlanError, PlanInput, validate_plan_input};
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
    fn accepts_valid_plan_input() {
        let validated = validate_plan_input(input()).expect("valid input");
        assert_eq!(validated.code, "vip");
        assert_eq!(validated.max_qps, Some(35));
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
    }

    #[test]
    fn treats_blank_description_as_none() {
        let mut value = input();
        value.description = Some("   ".to_owned());
        assert_eq!(validate_plan_input(value).expect("valid").description, None);
    }
}
