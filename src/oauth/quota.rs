use redis::Script;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use self::quota_keys::{period_keys, reservation_key};
use super::quota_scripts::{CONSUME_SCRIPT, REFUND_SCRIPT};
use crate::clock::{Clock, SystemClock};
use crate::plans::domain::AuthQuotaLimits;
use crate::{redis_client::RedisClient, redis_keyspace::RedisKeyspace};

#[path = "quota_keys.rs"]
mod quota_keys;
#[path = "quota_refund.rs"]
mod quota_refund;

/// 过期未兑换的授权码配额归还由后台 worker 执行（Issue #341）。
pub use quota_refund::{QUOTA_REFUND_WORKER_INTERVAL, QuotaRefundCancel, refund_due_unix_millis};

#[derive(Clone)]
pub struct OAuthQuotaStore {
    client: RedisClient,
    keyspace: RedisKeyspace,
}

/// 用量始终来自 Redis；上限来自生效套餐。
/// `daily_limit = None` 表示没有生效套餐（平台未开放自助接入），
/// `monthly_limit = None` 表示该维度无限。两者都序列化为 `null`，
/// 由前端渲染为「—」/「∞」，后端不编造 0。
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSnapshot {
    pub daily_limit: Option<u64>,
    pub daily_used: u64,
    pub monthly_limit: Option<u64>,
    pub monthly_used: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaConsumeResult {
    Allowed,
    DailyExceeded,
    MonthlyExceeded,
}

/// A successful quota reservation owns one increment in each period counter.
/// The period keys are retained so compensation cannot be redirected by a
/// clock boundary between consumption and refund.
///
/// 序列化能力服务于「过期未兑换则退款」台账（Issue #341）：签发时把
/// reservation 存进 Redis，后台 worker 到期后凭它执行 [`OAuthQuotaStore::refund`]。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuotaReservation {
    day_key: String,
    month_key: String,
    day_reservations_key: String,
    month_reservations_key: String,
    id: String,
    /// 月度计数器键的过期时刻（Unix 秒）。
    ///
    /// 待退记录必须活到月边界之后，才能覆盖「签发于 23:59、过期于次日 00:00
    /// 之后」的跨周期授权码；月计数器随该键一起过期，退款脚本对已过期的
    /// 周期自然退化为空操作。
    month_expires_at: i64,
}

impl QuotaReservation {
    pub fn id(&self) -> &str {
        &self.id
    }
}
pub struct QuotaConsumption {
    pub result: QuotaConsumeResult,
    reservation: Option<QuotaReservation>,
}
impl QuotaConsumption {
    pub fn reservation(self) -> Option<QuotaReservation> {
        self.reservation
    }
}
#[derive(Debug, Error)]
pub enum OAuthQuotaError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("redis quota script returned an invalid response")]
    InvalidResponse,
    #[error("quota limit is too large for Redis")]
    InvalidLimit,
    #[error("quota reservation serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl OAuthQuotaStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
            keyspace: RedisKeyspace::default(),
        }
    }

    pub fn with_keyspace(client: impl Into<RedisClient>, keyspace: RedisKeyspace) -> Self {
        Self {
            client: client.into(),
            keyspace,
        }
    }

    /// Consume one authorization using the effective plan's limits.
    pub async fn consume_with_limits(
        &self,
        client_id: &str,
        limits: AuthQuotaLimits,
    ) -> Result<QuotaConsumeResult, OAuthQuotaError> {
        self.consume_with_limits_and_reservation(client_id, limits)
            .await
            .map(|consumption| consumption.result)
    }

    /// 用进程默认时钟消费配额。
    ///
    /// 请求路径必须走 [`Self::consume_with_limits_and_reservation_at`] 并传入
    /// `AppState` 的共享时钟，否则周期键与同请求内的其它时间判定不同源；
    /// 这里保留墙钟只服务于不需要注入时钟的测试调用点。
    pub async fn consume_with_limits_and_reservation(
        &self,
        client_id: &str,
        limits: AuthQuotaLimits,
    ) -> Result<QuotaConsumption, OAuthQuotaError> {
        self.consume_with_limits_and_reservation_at(client_id, limits, SystemClock.now())
            .await
    }

    pub async fn consume_with_limits_at(
        &self,
        client_id: &str,
        limits: AuthQuotaLimits,
        now: OffsetDateTime,
    ) -> Result<QuotaConsumeResult, OAuthQuotaError> {
        self.consume_with_limits_and_reservation_at(client_id, limits, now)
            .await
            .map(|consumption| consumption.result)
    }

    pub async fn consume_with_limits_and_reservation_at(
        &self,
        client_id: &str,
        limits: AuthQuotaLimits,
        now: OffsetDateTime,
    ) -> Result<QuotaConsumption, OAuthQuotaError> {
        let (day_key, month_key, next_day, next_month) = self.period_keys(client_id, now)?;
        let day_reservations_key = reservation_key(&day_key);
        let month_reservations_key = reservation_key(&month_key);
        let reservation_id = Uuid::new_v4().simple().to_string();
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let result: Vec<i64> = Script::new(CONSUME_SCRIPT)
            .key(day_key.as_str())
            .key(month_key.as_str())
            .key(day_reservations_key.as_str())
            .key(month_reservations_key.as_str())
            .arg(redis_limit(Some(limits.daily_auth_limit))?)
            .arg(redis_limit(limits.monthly_auth_limit)?)
            .arg(next_day)
            .arg(next_month)
            .arg(reservation_id.as_str())
            .invoke_async(&mut connection)
            .await?;
        let result = match result.as_slice() {
            [1, 0, ..] => QuotaConsumeResult::Allowed,
            [0, 1, ..] => QuotaConsumeResult::DailyExceeded,
            [0, 2, ..] => QuotaConsumeResult::MonthlyExceeded,
            _ => return Err(OAuthQuotaError::InvalidResponse),
        };
        let reservation = match result {
            QuotaConsumeResult::Allowed => Some(QuotaReservation {
                day_key,
                month_key,
                day_reservations_key,
                month_reservations_key,
                id: reservation_id,
                month_expires_at: next_month,
            }),
            QuotaConsumeResult::DailyExceeded | QuotaConsumeResult::MonthlyExceeded => None,
        };
        Ok(QuotaConsumption {
            result,
            reservation,
        })
    }

    pub async fn refund(&self, reservation: &QuotaReservation) -> Result<(), OAuthQuotaError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: i64 = Script::new(REFUND_SCRIPT)
            .key(reservation.day_key.as_str())
            .key(reservation.month_key.as_str())
            .key(reservation.day_reservations_key.as_str())
            .key(reservation.month_reservations_key.as_str())
            .arg(reservation.id.as_str())
            .invoke_async(&mut connection)
            .await?;
        Ok(())
    }

    /// Read usage from Redis and attach the effective plan's limits.
    /// `limits = None` 表示没有生效套餐：仍然回报真实用量，但不给出上限。
    ///
    /// 用进程默认时钟读取用量快照。请求路径必须走 [`Self::snapshot_at`] 并传入
    /// `AppState` 的共享时钟；这里保留墙钟只服务于不需要注入时钟的测试调用点。
    pub async fn snapshot(
        &self,
        client_id: &str,
        limits: Option<AuthQuotaLimits>,
    ) -> Result<QuotaSnapshot, OAuthQuotaError> {
        self.snapshot_at(client_id, limits, SystemClock.now()).await
    }

    pub async fn snapshot_at(
        &self,
        client_id: &str,
        limits: Option<AuthQuotaLimits>,
        now: OffsetDateTime,
    ) -> Result<QuotaSnapshot, OAuthQuotaError> {
        let (day_key, month_key, _, _) = self.period_keys(client_id, now)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let (daily_used, monthly_used): (Option<u64>, Option<u64>) = redis::pipe()
            .cmd("GET")
            .arg(day_key)
            .cmd("GET")
            .arg(month_key)
            .query_async(&mut connection)
            .await?;
        Ok(QuotaSnapshot {
            daily_limit: limits.map(|limits| limits.daily_auth_limit),
            daily_used: daily_used.unwrap_or(0),
            monthly_limit: limits.and_then(|limits| limits.monthly_auth_limit),
            monthly_used: monthly_used.unwrap_or(0),
        })
    }
    fn period_keys(
        &self,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<(String, String, i64, i64), OAuthQuotaError> {
        period_keys(&self.keyspace, client_id, now)
    }
}

fn redis_limit(limit: Option<u64>) -> Result<i64, OAuthQuotaError> {
    limit
        .map(|limit| i64::try_from(limit).map_err(|_| OAuthQuotaError::InvalidLimit))
        .transpose()
        .map(|limit| limit.unwrap_or(-1))
}
