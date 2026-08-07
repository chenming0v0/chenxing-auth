use redis::Script;
use serde::Serialize;
use thiserror::Error;
use time::{Date, Month, OffsetDateTime, Time};
use uuid::Uuid;

use crate::clock::{Clock, SystemClock};
use crate::plans::domain::AuthQuotaLimits;
use crate::redis_client::RedisClient;

const CONSUME_SCRIPT: &str = r#"
local day = tonumber(redis.call('GET', KEYS[1]) or '0')
local month = tonumber(redis.call('GET', KEYS[2]) or '0')
local daily_limit = tonumber(ARGV[1])
local monthly_limit = tonumber(ARGV[2])
-- 负值表示该维度不设上限（套餐里 monthly_auth_limit 为 NULL）
if daily_limit >= 0 and day >= daily_limit then
  return {0, 1, day, month}
end
if monthly_limit >= 0 and month >= monthly_limit then
  return {0, 2, day, month}
end
local new_day = redis.call('INCR', KEYS[1])
local new_month = redis.call('INCR', KEYS[2])
redis.call('HSET', KEYS[3], ARGV[5], '1')
redis.call('HSET', KEYS[4], ARGV[5], '1')
if new_day == 1 then redis.call('EXPIREAT', KEYS[1], ARGV[3]) end
if new_month == 1 then redis.call('EXPIREAT', KEYS[2], ARGV[4]) end
redis.call('EXPIREAT', KEYS[3], ARGV[3])
redis.call('EXPIREAT', KEYS[4], ARGV[4])
return {1, 0, new_day, new_month}
"#;

const REFUND_SCRIPT: &str = r#"
local refunded = 0
local day = tonumber(redis.call('GET', KEYS[1]) or '0')
if day > 0 and redis.call('HDEL', KEYS[3], ARGV[1]) == 1 then
  redis.call('DECR', KEYS[1])
  refunded = 1
elseif day <= 0 then
  redis.call('HDEL', KEYS[3], ARGV[1])
end
local month = tonumber(redis.call('GET', KEYS[2]) or '0')
if month > 0 and redis.call('HDEL', KEYS[4], ARGV[1]) == 1 then
  redis.call('DECR', KEYS[2])
  refunded = 1
elseif month <= 0 then
  redis.call('HDEL', KEYS[4], ARGV[1])
end
return refunded
"#;

#[derive(Clone)]
pub struct OAuthQuotaStore {
    client: RedisClient,
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
pub struct QuotaReservation {
    day_key: String,
    month_key: String,
    day_reservations_key: String,
    month_reservations_key: String,
    id: String,
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
}

impl OAuthQuotaStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
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
        let (day_key, month_key, next_day, next_month) = period_keys(client_id, now)?;
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
        let (day_key, month_key, _, _) = period_keys(client_id, now)?;
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
}

fn redis_limit(limit: Option<u64>) -> Result<i64, OAuthQuotaError> {
    limit
        .map(|limit| i64::try_from(limit).map_err(|_| OAuthQuotaError::InvalidLimit))
        .transpose()
        .map(|limit| limit.unwrap_or(-1))
}
fn reservation_key(period_key: &str) -> String {
    format!("{period_key}:reservations")
}

fn period_keys(
    client_id: &str,
    now: OffsetDateTime,
) -> Result<(String, String, i64, i64), OAuthQuotaError> {
    let date = now.date();
    let next_day = date
        .next_day()
        .map(|date| date.with_time(Time::MIDNIGHT).assume_utc().unix_timestamp())
        .ok_or(OAuthQuotaError::InvalidResponse)?;
    let next_month_date = match date.month() {
        Month::December => Date::from_calendar_date(date.year() + 1, Month::January, 1),
        month => Date::from_calendar_date(
            date.year(),
            Month::try_from(month as u8 + 1).map_err(|_| OAuthQuotaError::InvalidResponse)?,
            1,
        ),
    }
    .map_err(|_| OAuthQuotaError::InvalidResponse)?;
    let next_month = next_month_date
        .with_time(Time::MIDNIGHT)
        .assume_utc()
        .unix_timestamp();
    Ok((
        format!("chenxing:oauth:quota:{client_id}:day:{date}"),
        format!(
            "chenxing:oauth:quota:{client_id}:month:{:04}-{:02}",
            date.year(),
            date.month() as u8
        ),
        next_day,
        next_month,
    ))
}

#[cfg(test)]
mod tests {
    use super::{OAuthQuotaStore, QuotaConsumeResult};
    use crate::plans::domain::AuthQuotaLimits;
    use uuid::Uuid;

    fn store() -> OAuthQuotaStore {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
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

    /// 没有生效套餐时快照仍然回报真实用量，但两个上限都是 `None`（序列化为 null）。
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
                    }
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
}
