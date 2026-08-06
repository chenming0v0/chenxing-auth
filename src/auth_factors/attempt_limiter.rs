//! 认证尝试的限流预留生命周期：维度构造、预留、提交失败与归还。
//!
//! TOTP 与 Passkey 用例共用同一套预留语义（reserve → record/release），把补偿路径
//! 集中在这里，才不用在每个用例里重复处理限流后端故障。

use super::{AuthFactorService, AuthFactorServiceError};
use crate::{
    auth_factors::repository,
    auth_limiter::{
        AuthFailureLimiter, FailureDimension, LimiterDimension, MissingSourceIpPolicy,
        domain::{AuthLimiterError, FailureRecord},
    },
    users::domain::UserId,
};

impl AuthFactorService {
    pub(super) async fn account_key(
        &self,
        user_id: UserId,
    ) -> Result<String, AuthFactorServiceError> {
        repository::find_user_email(&self.pool, user_id)
            .await?
            .ok_or(AuthFactorServiceError::UserNotFound)
    }

    pub(super) fn failure_dimensions(
        &self,
        account_key: &str,
        ticket_id: Option<&str>,
        source_ip: Option<&str>,
    ) -> Result<Vec<LimiterDimension>, AuthFactorServiceError> {
        let mut dimensions = vec![(FailureDimension::Account, account_key.to_owned())];
        if let Some(ticket_id) = ticket_id {
            dimensions.push((FailureDimension::Ticket, ticket_id.to_owned()));
        }
        match (source_ip, self.missing_source_ip_policy) {
            (Some(source_ip), _) => {
                dimensions.push((FailureDimension::SourceIp, source_ip.to_owned()))
            }
            (None, MissingSourceIpPolicy::Skip) => tracing::warn!(
                event = "auth_limiter.source_ip_unavailable",
                policy = MissingSourceIpPolicy::Skip.as_str(),
                "authentication factor attempt is using non-IP dimensions"
            ),
            (None, MissingSourceIpPolicy::Reject) => {
                tracing::error!(
                    event = "auth_limiter.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Reject.as_str(),
                    "authentication factor attempt rejected without trusted ConnectInfo"
                );
                return Err(AuthFactorServiceError::SourceIpUnavailable);
            }
        }
        Ok(dimensions)
    }

    /// 预留一次尝试。返回 true 表示已达上限、调用方必须直接拒绝；此时没有任何
    /// pending 计数需要归还。
    pub(super) async fn ensure_dimensions_allowed(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<bool, AuthFactorServiceError> {
        Ok(!self.limiter.reserve(dimensions).await?)
    }

    /// 把已预留的尝试提交为一次失败。限流后端出错时预留额度会被尽力归还，
    /// 不会悬挂到固定窗口过期。
    pub(super) async fn record_failure(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<FailureRecord, AuthFactorServiceError> {
        Ok(commit_reserved_failure(self.limiter.as_ref(), dimensions).await?)
    }

    pub(super) async fn release_dimensions(
        &self,
        dimensions: Vec<LimiterDimension>,
    ) -> Result<(), AuthFactorServiceError> {
        Ok(self.limiter.release(dimensions).await?)
    }

    /// 已经确定要返回错误时的归还路径：归还本身失败只记日志，不覆盖调用方手上
    /// 那个更本质的错误原因。
    pub(super) async fn release_dimensions_after_error(&self, dimensions: Vec<LimiterDimension>) {
        release_after_error(self.limiter.as_ref(), dimensions, "attempt_failed").await;
    }
}

/// 提交一次已预留的失败尝试。
///
/// `record_reserved_failures` 会在同一个 Lua 脚本里递减 pending 计数并递增失败计数。
/// 一旦这一步失败（Redis 抖动），`reserve` 留下的 pending 计数就既没被转记为失败、
/// 也没被归还，额度被凭空吃掉；窗口内反复抖动会把某个 IP 或账号的失败预算提前耗尽，
/// 把用户锁死在 RateLimited 上。所以出错时先尽力归还，再抛出原始错误。
///
/// 这里用显式补偿而不是 RAII 守卫：Rust 没有 async Drop，守卫无法在 `Drop` 里 await
/// Redis 调用，只能退化成 spawn 一个脱离请求生命周期的任务，反而更难推理。
async fn commit_reserved_failure(
    limiter: &dyn AuthFailureLimiter,
    dimensions: Vec<LimiterDimension>,
) -> Result<FailureRecord, AuthLimiterError> {
    match limiter.record_reserved_failures(dimensions.clone()).await {
        Ok(record) => Ok(record),
        Err(error) => {
            release_after_error(limiter, dimensions, "record_reserved_failures").await;
            Err(error)
        }
    }
}

/// 尽力归还预留额度。失败只上报可观测信号：悬挂的 pending 计数最迟随固定窗口
/// key 过期归零，用归还失败覆盖原始错误只会丢掉真实故障原因。
async fn release_after_error(
    limiter: &dyn AuthFailureLimiter,
    dimensions: Vec<LimiterDimension>,
    operation: &str,
) {
    let dimension_count = dimensions.len();
    if let Err(release_error) = limiter.release(dimensions).await {
        tracing::error!(
            event = "auth_limiter.reservation_release_failed",
            operation,
            dimensions = dimension_count,
            error = %release_error,
            "reserved authentication quota was not released; pending counters expire with the window"
        );
    }
}

#[cfg(test)]
#[path = "attempt_limiter_tests.rs"]
mod tests;
