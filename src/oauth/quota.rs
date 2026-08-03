use redis::{Client, Script};
use serde::Serialize;
use thiserror::Error;
use time::{Date, Month, OffsetDateTime, Time};

use crate::plans::domain::AuthQuotaLimits;

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
if new_day == 1 then redis.call('EXPIREAT', KEYS[1], ARGV[3]) end
if new_month == 1 then redis.call('EXPIREAT', KEYS[2], ARGV[4]) end
return {1, 0, new_day, new_month}
"#;

const REFUND_SCRIPT: &str = r#"
local day = tonumber(redis.call('GET', KEYS[1]) or '0')
local month = tonumber(redis.call('GET', KEYS[2]) or '0')
if day > 0 then redis.call('DECR', KEYS[1]) end
if month > 0 then redis.call('DECR', KEYS[2]) end
return 1
"#;

#[derive(Clone)]
pub struct OAuthQuotaStore {
    client: Client,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuotaSnapshot {
    pub daily_limit: u64,
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
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Consume one authorization using the effective plan's limits.
    pub async fn consume_with_limits(
        &self,
        client_id: &str,
        limits: AuthQuotaLimits,
    ) -> Result<QuotaConsumeResult, OAuthQuotaError> {
        let now = OffsetDateTime::now_utc();
        let (day_key, month_key, next_day, next_month) = period_keys(client_id, now)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let result: Vec<i64> = Script::new(CONSUME_SCRIPT)
            .key(day_key)
            .key(month_key)
            .arg(redis_limit(Some(limits.daily_auth_limit))?)
            .arg(redis_limit(limits.monthly_auth_limit)?)
            .arg(next_day)
            .arg(next_month)
            .invoke_async(&mut connection)
            .await?;
        match result.as_slice() {
            [1, 0, ..] => Ok(QuotaConsumeResult::Allowed),
            [0, 1, ..] => Ok(QuotaConsumeResult::DailyExceeded),
            [0, 2, ..] => Ok(QuotaConsumeResult::MonthlyExceeded),
            _ => Err(OAuthQuotaError::InvalidResponse),
        }
    }

    pub async fn refund(&self, client_id: &str) -> Result<(), OAuthQuotaError> {
        let now = OffsetDateTime::now_utc();
        let (day_key, month_key, _, _) = period_keys(client_id, now)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: i64 = Script::new(REFUND_SCRIPT)
            .key(day_key)
            .key(month_key)
            .invoke_async(&mut connection)
            .await?;
        Ok(())
    }

    /// Read usage from Redis and attach the effective plan's limits.
    pub async fn snapshot(
        &self,
        client_id: &str,
        limits: AuthQuotaLimits,
    ) -> Result<QuotaSnapshot, OAuthQuotaError> {
        let now = OffsetDateTime::now_utc();
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
            daily_limit: limits.daily_auth_limit,
            daily_used: daily_used.unwrap_or(0),
            monthly_limit: limits.monthly_auth_limit,
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
                AuthQuotaLimits {
                    daily_auth_limit: 7,
                    monthly_auth_limit: Some(11),
                },
            )
            .await
            .expect("empty quota snapshot");
        assert_eq!(snapshot.daily_limit, 7);
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
        let snapshot = store.snapshot(&client_id, limits).await.expect("snapshot");
        assert_eq!(snapshot.daily_limit, 3);
        assert_eq!(snapshot.daily_used, 1);
        assert_eq!(snapshot.monthly_limit, None);
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
                AuthQuotaLimits {
                    daily_auth_limit: 1,
                    monthly_auth_limit: Some(1),
                },
            )
            .await;
        assert!(result.is_err());
    }
}
