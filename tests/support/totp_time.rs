#![allow(dead_code)]

use time::OffsetDateTime;

const STEP_SECONDS: i64 = 30;
const STEP_CENTER_SECONDS: i64 = 15;

pub fn centered_now() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let centered = now.div_euclid(STEP_SECONDS) * STEP_SECONDS + STEP_CENTER_SECONDS;
    OffsetDateTime::from_unix_timestamp(centered).expect("centered TOTP test time")
}

pub fn previous_timestep(now: OffsetDateTime) -> u64 {
    u64::try_from(now.unix_timestamp().saturating_sub(STEP_SECONDS))
        .expect("positive TOTP test timestamp")
}
