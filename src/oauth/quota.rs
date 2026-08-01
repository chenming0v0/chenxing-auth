use redis::{Client, Script};
use serde::Serialize;
use thiserror::Error;
use time::{Date, Month, OffsetDateTime, Time};

pub const DAILY_AUTHORIZATION_LIMIT: u64 = 2_500;
pub const MONTHLY_AUTHORIZATION_LIMIT: u64 = 50_000;

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
    pub monthly_limit: u64,
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
}

impl OAuthQuotaStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn consume(&self, client_id: &str) -> Result<QuotaConsumeResult, OAuthQuotaError> {
        self.consume_with_limits(
            client_id,
            Some(DAILY_AUTHORIZATION_LIMIT),
            Some(MONTHLY_AUTHORIZATION_LIMIT),
        )
        .await
    }

    /// 按套餐限额消费授权配额。`None` 表示该维度不限（对应套餐里
    /// `monthly_auth_limit` 为 `NULL` 的语义）。
    pub async fn consume_with_limits(
        &self,
        client_id: &str,
        daily_limit: Option<u64>,
        monthly_limit: Option<u64>,
    ) -> Result<QuotaConsumeResult, OAuthQuotaError> {
        let now = OffsetDateTime::now_utc();
        let (day_key, month_key, next_day, next_month) = period_keys(client_id, now)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let result: Vec<i64> = Script::new(CONSUME_SCRIPT)
            .key(day_key)
            .key(month_key)
            .arg(daily_limit.map(|limit| limit as i64).unwrap_or(-1))
            .arg(monthly_limit.map(|limit| limit as i64).unwrap_or(-1))
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

    pub async fn snapshot(&self, client_id: &str) -> Result<QuotaSnapshot, OAuthQuotaError> {
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
            daily_limit: DAILY_AUTHORIZATION_LIMIT,
            daily_used: daily_used.unwrap_or(0),
            monthly_limit: MONTHLY_AUTHORIZATION_LIMIT,
            monthly_used: monthly_used.unwrap_or(0),
        })
    }
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
    use uuid::Uuid;

    fn store() -> OAuthQuotaStore {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        OAuthQuotaStore::new(redis::Client::open(url).expect("Redis URL"))
    }

    #[tokio::test]
    async fn custom_limits_reject_daily_and_monthly_overages() {
        let store = store();
        let daily_client = format!("quota-daily-{}", Uuid::new_v4().simple());
        assert_eq!(
            store
                .consume_with_limits(&daily_client, Some(2), Some(10))
                .await
                .expect("first quota use"),
            QuotaConsumeResult::Allowed
        );
        assert_eq!(
            store
                .consume_with_limits(&daily_client, Some(2), Some(10))
                .await
                .expect("second quota use"),
            QuotaConsumeResult::Allowed
        );
        assert_eq!(
            store
                .consume_with_limits(&daily_client, Some(2), Some(10))
                .await
                .expect("daily quota rejection"),
            QuotaConsumeResult::DailyExceeded
        );

        let monthly_client = format!("quota-monthly-{}", Uuid::new_v4().simple());
        assert_eq!(
            store
                .consume_with_limits(&monthly_client, Some(10), Some(2))
                .await
                .expect("first monthly use"),
            QuotaConsumeResult::Allowed
        );
        assert_eq!(
            store
                .consume_with_limits(&monthly_client, Some(10), Some(2))
                .await
                .expect("second monthly use"),
            QuotaConsumeResult::Allowed
        );
        assert_eq!(
            store
                .consume_with_limits(&monthly_client, Some(10), Some(2))
                .await
                .expect("monthly quota rejection"),
            QuotaConsumeResult::MonthlyExceeded
        );
    }

    #[tokio::test]
    async fn null_monthly_limit_never_rejects_monthly() {
        let store = store();
        let client_id = format!("quota-unlimited-monthly-{}", Uuid::new_v4().simple());
        for _ in 0..5 {
            assert_eq!(
                store
                    .consume_with_limits(&client_id, Some(10), None)
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
        let (first, second, third) = tokio::join!(
            store.consume_with_limits(&client_id, Some(2), Some(10)),
            store.consume_with_limits(&client_id, Some(2), Some(10)),
            store.consume_with_limits(&client_id, Some(2), Some(10)),
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
}
