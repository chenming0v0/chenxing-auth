use time::OffsetDateTime;

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock(pub OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, FixedClock, SystemClock};
    use time::OffsetDateTime;

    #[test]
    fn fixed_clock_returns_the_configured_time() {
        let fixed = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(FixedClock(fixed).now(), fixed);
    }

    #[test]
    fn system_clock_reads_current_utc_time() {
        let before = OffsetDateTime::now_utc();
        let now = SystemClock.now();
        let after = OffsetDateTime::now_utc();

        assert!(before <= now && now <= after);
    }
}
