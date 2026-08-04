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
pub enum AuthLimiterFailurePolicy {
    FailOpen,
    FailClosed,
}

impl AuthLimiterFailurePolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailOpen => "fail-open",
            Self::FailClosed => "fail-closed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingSourceIpPolicy {
    Skip,
    Reject,
}

impl MissingSourceIpPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Reject => "reject",
        }
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureRecord {
    pub reached: Vec<FailureDimension>,
}

impl FailureRecord {
    pub fn reached(&self, dimension: FailureDimension) -> bool {
        self.reached.contains(&dimension)
    }
}

pub type LimiterDimension = (FailureDimension, String);

pub type LimiterFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AuthLimiterError>> + Send + 'a>>;

/// Application-facing boundary for authentication failure counters.
pub trait AuthFailureLimiter: Send + Sync {
    fn is_limited<'a>(
        &'a self,
        dimension: FailureDimension,
        value: &str,
    ) -> LimiterFuture<'a, bool>;

    /// Returns true when this failure reaches the dimension's limit.
    fn record_failure<'a>(
        &'a self,
        dimension: FailureDimension,
        value: &str,
    ) -> LimiterFuture<'a, bool>;

    fn clear<'a>(&'a self, dimension: FailureDimension, value: &str) -> LimiterFuture<'a, ()>;

    /// Atomically reserves one authentication attempt across all dimensions.
    /// The result is false when a dimension is already at its limit.
    fn reserve<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, bool> {
        Box::pin(async move {
            if self.any_limited(dimensions).await? {
                Ok(false)
            } else {
                Ok(true)
            }
        })
    }

    /// Commits a previously reserved attempt as a failed authentication.
    fn record_reserved_failures<'a>(
        &'a self,
        dimensions: Vec<LimiterDimension>,
    ) -> LimiterFuture<'a, FailureRecord> {
        self.record_failures(dimensions)
    }

    /// Releases a previously reserved attempt after successful authentication.
    fn release<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, ()> {
        Box::pin(async move {
            let _ = dimensions;
            Ok(())
        })
    }

    /// Checks all dimensions in one logical operation. Implementations backed by
    /// Redis override this with one Lua invocation; the default keeps test
    /// doubles and other storage adapters source-compatible.
    fn any_limited<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, bool> {
        Box::pin(async move {
            for (dimension, value) in dimensions {
                if self.is_limited(dimension, &value).await? {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// Records one failed authentication against all applicable dimensions and
    /// returns the dimensions that reached their threshold.
    fn record_failures<'a>(
        &'a self,
        dimensions: Vec<LimiterDimension>,
    ) -> LimiterFuture<'a, FailureRecord> {
        Box::pin(async move {
            let mut reached = Vec::new();
            for (dimension, value) in dimensions {
                if self.record_failure(dimension, &value).await? {
                    reached.push(dimension);
                }
            }
            Ok(FailureRecord { reached })
        })
    }
}
