//! 认证尝试的限流预留生命周期：维度构造、预留、提交失败与归还。
//!
//! TOTP 与 Passkey 用例共用同一套预留语义（reserve → record/release），把补偿路径
//! 集中在这里，才不用在每个用例里重复处理限流后端故障。

use super::{AuthFactorService, AuthFactorServiceError};
use crate::{
    auth_factors::repository,
    auth_limiter::{
        AuthFailureLimiter, AuthReservation, FailureDimension, LimiterDimension, MissingSourceIpPolicy,
        domain::{FailureRecord, commit_reserved_failure, release_reserved},
    },
    users::domain::UserId,
};

impl AuthFactorService {
    pub(super) async fn account_key(
        &self,
        user_id: UserId,
    ) -> Result<String, AuthFactorServiceError> {
        repository::find_user_canonical_email(&self.pool, user_id)
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
    ) -> Result<Option<AuthReservation>, AuthFactorServiceError> {
        let reservation = self.limiter.reserve(dimensions).await?;
        Ok((!reservation.is_empty()).then_some(reservation))
    }

    /// 把已预留的尝试提交为一次失败。限流后端出错时预留额度会被尽力归还，
    /// 不会悬挂到 pending 计数器的 TTL 过期。
    pub(super) async fn record_failure(
        &self,
        reservation: AuthReservation,
    ) -> Result<FailureRecord, AuthFactorServiceError> {
        Ok(commit_reserved_failure(self.limiter.as_ref(), reservation).await?)
    }

    pub(super) async fn release_dimensions(
        &self,
        reservation: AuthReservation,
    ) -> Result<(), AuthFactorServiceError> {
        Ok(self.limiter.release(reservation).await?)
    }

    pub(super) async fn release_dimensions_after_error(&self, reservation: AuthReservation) {
        release_reserved(self.limiter.as_ref(), reservation, "attempt_failed").await;
    }

    pub(super) async fn release_dimensions_for_key_unavailable(
        &self,
        reservation: AuthReservation,
    ) {
        release_key_unavailable(self.limiter.as_ref(), reservation).await;
    }

    pub(super) async fn release_dimensions_for_missing_factor(
        &self,
        reservation: AuthReservation,
    ) {
        release_factor_missing(self.limiter.as_ref(), reservation).await;
    }
}

/// kid 退役导致的不可验证：归还预留额度，**不记账**（#258）。
///
/// 这不是用户的失败尝试，而是服务端缺少密钥材料。把它计入账户或 IP 计数会让
/// 一次运维动作把用户从「TOTP 不可用」升级为「连密码登录都被限流」，等于用限流
/// 惩罚受害者。抽成自由函数是为了能用测试替身断言「只 release、绝不 record」。
pub(super) async fn release_key_unavailable(
    limiter: &dyn AuthFailureLimiter,
    reservation: AuthReservation,
) {
    release_reserved(limiter, reservation, "factor_key_unavailable").await;
}

/// 账号没有 TOTP 因子时的归还：归还预留额度，**不记账**（#340）。
///
/// 「因子不存在」不是一次用户失败：调用方刚从 `available_methods` 看到因子，
/// 这里却读不到，是管理员重置/删除与读取之间的竞态，或客户端仍按旧状态提交
/// 验证码。没有因子就没有可校验的密钥，重试永远失败，不存在可爆破的目标；
/// 把它计入账号维度会烧掉与密码失败共享的额度，10 次后连密码登录也被锁
/// 15 分钟——等于用限流惩罚受害者（与 #258 的 kid 退役同一原则）。抽成自由
/// 函数是为了能用测试替身断言「只 release、绝不 record」。
pub(super) async fn release_factor_missing(
    limiter: &dyn AuthFailureLimiter,
    reservation: AuthReservation,
) {
    release_reserved(limiter, reservation, "factor_missing").await;
}

#[cfg(test)]
#[path = "attempt_limiter_tests.rs"]
mod tests;
