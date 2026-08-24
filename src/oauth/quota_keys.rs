use time::{Date, Month, OffsetDateTime, Time};

use super::OAuthQuotaError;
use crate::redis_keyspace::RedisKeyspace;

/// 待退台账 ZSET：member = reservation id，score = 授权码过期时刻（Unix 毫秒）。
pub(super) const PENDING_REFUNDS_ZSET: &str = "chenxing:oauth:quota:refund-pending";

pub(super) fn reservation_key(period_key: &str) -> String {
    format!("{period_key}:reservations")
}

pub(super) fn reservation_record_key(keyspace: &RedisKeyspace, reservation_id: &str) -> String {
    keyspace.key(&format!(
        "chenxing:oauth:quota:reservation:{reservation_id}"
    ))
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

/// Merge the two on-disk score formats fairly so a full modern queue cannot
/// starve upgrade-era legacy reservations. Legacy entries lead each pair to
/// guarantee progress even when the batch is filled on every pass.
pub(super) fn fair_merge_due(
    modern: Vec<String>,
    legacy: Vec<String>,
    batch_size: usize,
) -> Vec<String> {
    let mut due = Vec::with_capacity(batch_size);
    let mut modern_index = 0;
    let mut legacy_index = 0;
    while due.len() < batch_size && (modern_index < modern.len() || legacy_index < legacy.len()) {
        if let Some(reservation_id) = legacy.get(legacy_index) {
            due.push(reservation_id.clone());
            legacy_index += 1;
        }
        if due.len() >= batch_size {
            break;
        }
        if let Some(reservation_id) = modern.get(modern_index) {
            due.push(reservation_id.clone());
            modern_index += 1;
        }
    }
    due
}
