use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

/// `oauth_clients_limit` 的合理上界（Issue #415）。
///
/// 远超任何真实套餐档位（种子套餐为 1–2），同时把单用户 Client 规模约束在
/// 用户端列表分页（每页最多 200）可完整枚举的范围内，杜绝「配额 > 列表上限」
/// 这一配置可达的静默截断状态。
pub const MAX_OAUTH_CLIENTS_LIMIT: i32 = 1000;

/// `daily_auth_limit` 的合理上界（Issue #459）。
///
/// 授权发放是交互式用户动作，不是机器对机器的吞吐。种子套餐是 2500/天；
/// 100 万/天/Client 约等于持续 11.5 次/秒，已经超过任何真实 SSO 车队。
/// 这一列是 `NOT NULL` 且没有「无限」哨兵，所以上界就是可配置的天花板。
pub const MAX_DAILY_AUTH_LIMIT: i64 = 1_000_000;

/// `monthly_auth_limit` 的合理上界（Issue #459）。
///
/// 等于 `31 × MAX_DAILY_AUTH_LIMIT`，允许套餐在 31 天的月份里每天都打满日上限。
/// 需要更高就设 `NULL`（无限）。种子套餐是 50_000。
pub const MAX_MONTHLY_AUTH_LIMIT: i64 = 31_000_000;

/// `max_qps` 的合理上界（Issue #459）。
///
/// Token 端点按 Client 的滑动窗口限流。文档示例是 35；10_000 已经是认证
/// 服务的攻击流量量级。需要更高就设 `NULL`（不限）。显式 0 没有意义。
pub const MAX_QPS: i32 = 10_000;

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
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
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
            daily_auth_limit: unsigned_quota(self.daily_auth_limit),
            monthly_auth_limit: self.monthly_auth_limit.map(unsigned_quota),
        }
    }
}

/// 把持久化配额转成配额存储使用的无符号值。
///
/// 负值是数据完整性错误。以前的 `.max(0)` 会把它变成真实的「拒绝全部授权」
/// 配额，绕过服务层写入负数就能对挂了该套餐的 Client 造成拒绝服务
/// （Issue #459）。数据库 CHECK 现在拒绝这种写入；如果负值仍然出现，
/// 宁可崩溃也不要发明 0。
fn unsigned_quota(limit: i64) -> u64 {
    u64::try_from(limit).unwrap_or_else(|_| {
        panic!(
            "plan quota {limit} is negative; refusing to clamp it to 0 \
             (that would deny all authorizations)"
        )
    })
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
    #[error(
        "daily authorization limit must be between 0 and {}",
        MAX_DAILY_AUTH_LIMIT
    )]
    InvalidDailyLimit,
    #[error(
        "monthly authorization limit must be between 0 and {}, or null for unlimited",
        MAX_MONTHLY_AUTH_LIMIT
    )]
    InvalidMonthlyLimit,
    #[error("max QPS must be between 1 and {}, or null for unlimited", MAX_QPS)]
    InvalidMaxQps,
    #[error("plan expiration must be in the future")]
    ExpiryInPast,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanMutationError {
    #[error("archived plans cannot be default")]
    ArchivedPlanCannotBeDefault,
    #[error("archived plans cannot be assigned to users")]
    PlanArchived,
}

/// 归档套餐不能被设为默认。这里先给出 409，避免依赖
/// `plans_default_must_be_active` CHECK 抛出数据库错误变成 500。
pub fn validate_plan_update(
    plan: &Plan,
    input: &ValidatedPlanInput,
) -> Result<(), PlanMutationError> {
    if input.is_default && plan.status != "active" {
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
    // 无上界校验时，配额可配到 i32 上限（约 21 亿），远超用户端列表 200 条/页的分页
    // 能力，超出部分对 owner 不可见也不可管理；加上界封死该状态（Issue #415）。
    if !(0..=MAX_OAUTH_CLIENTS_LIMIT).contains(&input.oauth_clients_limit) {
        return Err(PlanError::InvalidOauthClientsLimit);
    }
    if !(0..=MAX_DAILY_AUTH_LIMIT).contains(&input.daily_auth_limit) {
        return Err(PlanError::InvalidDailyLimit);
    }
    if input
        .monthly_auth_limit
        .is_some_and(|limit| !(0..=MAX_MONTHLY_AUTH_LIMIT).contains(&limit))
    {
        return Err(PlanError::InvalidMonthlyLimit);
    }
    // `max_qps` 为 `NULL` 表示不限并发；显式 0 没有意义且会拒绝所有请求。
    if input
        .max_qps
        .is_some_and(|qps| !(1..=MAX_QPS).contains(&qps))
    {
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
#[path = "domain_tests.rs"]
mod tests;
