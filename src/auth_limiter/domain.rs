use std::{future::Future, pin::Pin};

use thiserror::Error;

/// Fixed-window duration shared by account, IP, and login-ticket counters.
pub const AUTH_FAILURE_WINDOW_SECONDS: i64 = 15 * 60;
/// Account failures allowed in one window before the next attempt is blocked.
pub const ACCOUNT_FAILURE_LIMIT: i64 = 10;
/// Source-IP failures allowed in one window before the next attempt is blocked.
pub const IP_FAILURE_LIMIT: i64 = 30;
/// TOTP failures allowed for one pending login ticket before it is invalidated.
pub const TOTP_TICKET_FAILURE_LIMIT: i64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureDimension {
    Account,
    SourceIp,
    Ticket,
}

impl FailureDimension {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::SourceIp => "source_ip",
            Self::Ticket => "ticket",
        }
    }

    pub const fn limit(self) -> i64 {
        match self {
            Self::Account => ACCOUNT_FAILURE_LIMIT,
            Self::SourceIp => IP_FAILURE_LIMIT,
            Self::Ticket => TOTP_TICKET_FAILURE_LIMIT,
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthLimiterError {
    #[error("authentication limiter storage is unavailable")]
    Storage,
}

pub type LimiterFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AuthLimiterError>> + Send + 'a>>;

/// Application-facing boundary for authentication failure counters.
pub trait AuthFailureLimiter: Send + Sync {
    fn is_limited<'a>(
        &'a self,
        dimension: FailureDimension,
        value: &'a str,
    ) -> LimiterFuture<'a, bool>;

    /// Returns true when this failure reaches the dimension's limit.
    fn record_failure<'a>(
        &'a self,
        dimension: FailureDimension,
        value: &'a str,
    ) -> LimiterFuture<'a, bool>;

    fn clear<'a>(&'a self, dimension: FailureDimension, value: &'a str) -> LimiterFuture<'a, ()>;
}
