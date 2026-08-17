use time::{Date, Month, OffsetDateTime, Time};

use super::OAuthQuotaError;
use crate::redis_keyspace::RedisKeyspace;

pub(super) fn reservation_key(period_key: &str) -> String {
    format!("{period_key}:reservations")
}

pub(super) fn period_keys(
    keyspace: &RedisKeyspace,
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
        keyspace.key(&format!("chenxing:oauth:quota:{client_id}:day:{date}")),
        keyspace.key(&format!(
            "chenxing:oauth:quota:{client_id}:month:{:04}-{:02}",
            date.year(),
            date.month() as u8
        )),
        next_day,
        next_month,
    ))
}
