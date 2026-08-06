use ::redis::Script;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

use super::domain::{
    AuthFailureLimiter, AuthFailureLimits, AuthLimiterError, AuthLimiterFailurePolicy,
    FailureDimension, FailureRecord, LimiterDimension, LimiterFuture,
};
use crate::settings::SettingsService;

const FAILURE_KEY_PREFIX: &str = "chenxing:auth:failure:";
const PENDING_KEY_PREFIX: &str = "chenxing:auth:pending:";
use super::redis_scripts::*;
use crate::redis_client::RedisClient;

static REDIS_ERRORS: AtomicU64 = AtomicU64::new(0);
static LIMIT_HITS: AtomicU64 = AtomicU64::new(0);
static FAILURE_RECORDS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthLimiterMetrics {
    pub redis_errors: u64,
    pub limit_hits: u64,
    pub failure_records: u64,
}

pub fn metrics() -> AuthLimiterMetrics {
    AuthLimiterMetrics {
        redis_errors: REDIS_ERRORS.load(Ordering::Relaxed),
        limit_hits: LIMIT_HITS.load(Ordering::Relaxed),
        failure_records: FAILURE_RECORDS.load(Ordering::Relaxed),
    }
}

#[derive(Clone)]
pub struct RedisAuthFailureLimiter {
    client: RedisClient,
    failure_policy: AuthLimiterFailurePolicy,
    limits: AuthFailureLimits,
    settings: Option<SettingsService>,
}

impl RedisAuthFailureLimiter {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self::with_failure_policy(client, AuthLimiterFailurePolicy::FailClosed)
    }

    pub fn with_failure_policy(
        client: impl Into<RedisClient>,
        failure_policy: AuthLimiterFailurePolicy,
    ) -> Self {
        Self::with_limits(client, failure_policy, AuthFailureLimits::default())
    }

    pub fn with_limits(
        client: impl Into<RedisClient>,
        failure_policy: AuthLimiterFailurePolicy,
        limits: AuthFailureLimits,
    ) -> Self {
        Self {
            client: client.into(),
            failure_policy,
            limits,
            settings: None,
        }
    }

    pub fn with_settings(
        client: impl Into<RedisClient>,
        failure_policy: AuthLimiterFailurePolicy,
        settings: SettingsService,
    ) -> Self {
        Self {
            client: client.into(),
            failure_policy,
            limits: AuthFailureLimits::default(),
            settings: Some(settings),
        }
    }

    async fn current_limits(&self) -> Result<AuthFailureLimits, AuthLimiterError> {
        let Some(settings) = &self.settings else {
            return Ok(self.limits);
        };
        let value = settings.security_limits().await.map_err(|error_value| {
            tracing::error!(
                error = %error_value,
                "failed to load security limits for authentication limiter"
            );
            AuthLimiterError::Storage
        })?;
        Ok(AuthFailureLimits {
            window_seconds: value.auth_failure_window_seconds,
            account_limit: value.account_failure_limit,
            ip_limit: value.ip_failure_limit,
            ticket_limit: value.totp_ticket_failure_limit,
        })
    }

    fn value_hash(value: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
    }

    fn base_key(dimension: FailureDimension, value: &str) -> String {
        format!(
            "{FAILURE_KEY_PREFIX}{}:{}",
            dimension.as_str(),
            Self::value_hash(value)
        )
    }

    fn base_pending_key(dimension: FailureDimension, value: &str) -> String {
        format!(
            "{PENDING_KEY_PREFIX}{}:{}",
            dimension.as_str(),
            Self::value_hash(value)
        )
    }

    fn log_limit(dimension: FailureDimension, value: &str, window: i64) {
        LIMIT_HITS.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            event = "auth_limiter.limit_reached",
            dimension = dimension.as_str(),
            key_hash = %Self::value_hash(value),
            window,
            "authentication failure limit triggered"
        );
    }

    fn log_storage_error(&self, operation: &str, dimensions: &[LimiterDimension]) {
        REDIS_ERRORS.fetch_add(1, Ordering::Relaxed);
        let dimension = dimensions
            .first()
            .map_or("none", |(dimension, _)| dimension.as_str());
        tracing::error!(
            event = "auth_limiter.redis_unavailable",
            operation,
            dimension,
            dimensions = dimensions.len(),
            policy = self.failure_policy.as_str(),
            "authentication limiter storage operation failed"
        );
    }

    fn unavailable_bool(
        &self,
        operation: &str,
        dimensions: &[LimiterDimension],
    ) -> Result<bool, AuthLimiterError> {
        self.log_storage_error(operation, dimensions);
        match self.failure_policy {
            AuthLimiterFailurePolicy::FailOpen => Ok(false),
            AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
        }
    }

    fn unavailable_record(
        &self,
        operation: &str,
        dimensions: &[LimiterDimension],
    ) -> Result<FailureRecord, AuthLimiterError> {
        self.log_storage_error(operation, dimensions);
        match self.failure_policy {
            AuthLimiterFailurePolicy::FailOpen => Ok(FailureRecord {
                reached: Vec::new(),
            }),
            AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
        }
    }

    fn unavailable_reservation(
        &self,
        operation: &str,
        dimensions: &[LimiterDimension],
    ) -> Result<bool, AuthLimiterError> {
        self.log_storage_error(operation, dimensions);
        match self.failure_policy {
            AuthLimiterFailurePolicy::FailOpen => Ok(true),
            AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
        }
    }
}

impl AuthFailureLimiter for RedisAuthFailureLimiter {
    fn is_limited<'a>(
        &'a self,
        dimension: FailureDimension,
        value: &str,
    ) -> LimiterFuture<'a, bool> {
        let value = value.to_owned();
        Box::pin(async move { self.any_limited(vec![(dimension, value)]).await })
    }

    fn record_failure<'a>(
        &'a self,
        dimension: FailureDimension,
        value: &str,
    ) -> LimiterFuture<'a, bool> {
        let value = value.to_owned();
        Box::pin(async move {
            let record = self.record_failures(vec![(dimension, value)]).await?;
            Ok(record.reached(dimension))
        })
    }

    fn clear<'a>(&'a self, dimension: FailureDimension, value: &str) -> LimiterFuture<'a, ()> {
        let value = value.to_owned();
        Box::pin(async move {
            let limits = self.current_limits().await?;
            let dimensions = [(dimension, value.clone())];
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => {
                    self.log_storage_error("clear", &dimensions);
                    return match self.failure_policy {
                        AuthLimiterFailurePolicy::FailOpen => Ok(()),
                        AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
                    };
                }
            };
            let script = Script::new(CLEAR_FAILURE_SCRIPT);
            let mut invocation = script.prepare_invoke();
            invocation.key(Self::base_key(dimension, &value));
            invocation.arg(limits.window());
            let result: Result<i64, _> = invocation.invoke_async(&mut connection).await;
            if result.is_err() {
                self.log_storage_error("clear", &dimensions);
                if matches!(self.failure_policy, AuthLimiterFailurePolicy::FailClosed) {
                    return Err(AuthLimiterError::Storage);
                }
            }
            Ok(())
        })
    }

    fn any_limited<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, bool> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(false);
            }
            let limits = self.current_limits().await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.unavailable_bool("check", &dimensions),
            };
            let script = Script::new(CHECK_LIMITS_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(Self::base_key(*dimension, value));
            }
            invocation.arg(limits.window());
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            let result: Vec<i64> = match invocation.invoke_async(&mut connection).await {
                Ok(result) => result,
                Err(_) => return self.unavailable_bool("check", &dimensions),
            };
            let (limited, window) = match result.as_slice() {
                [limited, window] => (*limited, *window),
                _ => return self.unavailable_bool("check", &dimensions),
            };
            if limited == 1 {
                for (dimension, value) in &dimensions {
                    Self::log_limit(*dimension, value, window);
                }
            }
            Ok(limited == 1)
        })
    }

    fn record_failures<'a>(
        &'a self,
        dimensions: Vec<LimiterDimension>,
    ) -> LimiterFuture<'a, FailureRecord> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(FailureRecord {
                    reached: Vec::new(),
                });
            }
            let limits = self.current_limits().await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.unavailable_record("record", &dimensions),
            };
            let script = Script::new(RECORD_FAILURE_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(Self::base_key(*dimension, value));
            }
            invocation.arg(limits.window());
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            let result: Vec<i64> = match invocation.invoke_async(&mut connection).await {
                Ok(result) => result,
                Err(_) => return self.unavailable_record("record", &dimensions),
            };
            let (window, flags) = match result.split_last() {
                Some((window, flags)) if flags.len() == dimensions.len() => (*window, flags),
                _ => return self.unavailable_record("record", &dimensions),
            };
            FAILURE_RECORDS.fetch_add(dimensions.len() as u64, Ordering::Relaxed);
            let reached = dimensions
                .iter()
                .zip(flags.iter().copied())
                .filter_map(|((dimension, value), flag)| {
                    if flag == 1 {
                        Self::log_limit(*dimension, value, window);
                        Some(*dimension)
                    } else {
                        None
                    }
                })
                .collect();
            Ok(FailureRecord { reached })
        })
    }

    fn reserve<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, bool> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(true);
            }
            let limits = self.current_limits().await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.unavailable_reservation("reserve", &dimensions),
            };
            let script = Script::new(RESERVE_ATTEMPT_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(Self::base_key(*dimension, value));
            }
            for (dimension, value) in &dimensions {
                invocation.key(Self::base_pending_key(*dimension, value));
            }
            invocation.arg(dimensions.len());
            invocation.arg(limits.window());
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            let result: Vec<i64> = match invocation.invoke_async(&mut connection).await {
                Ok(result) => result,
                Err(_) => return self.unavailable_reservation("reserve", &dimensions),
            };
            let (reserved, window) = match result.as_slice() {
                [reserved, window] => (*reserved, *window),
                _ => return self.unavailable_reservation("reserve", &dimensions),
            };
            if reserved == 0 {
                for (dimension, value) in &dimensions {
                    Self::log_limit(*dimension, value, window);
                }
            }
            Ok(reserved == 1)
        })
    }

    fn record_reserved_failures<'a>(
        &'a self,
        dimensions: Vec<LimiterDimension>,
    ) -> LimiterFuture<'a, FailureRecord> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(FailureRecord {
                    reached: Vec::new(),
                });
            }
            let limits = self.current_limits().await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => return self.unavailable_record("record_reserved", &dimensions),
            };
            let script = Script::new(RECORD_RESERVED_FAILURE_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(Self::base_key(*dimension, value));
            }
            for (dimension, value) in &dimensions {
                invocation.key(Self::base_pending_key(*dimension, value));
            }
            invocation.arg(dimensions.len());
            invocation.arg(limits.window());
            for (dimension, _) in &dimensions {
                invocation.arg(limits.limit_for(*dimension));
            }
            let result: Vec<i64> = match invocation.invoke_async(&mut connection).await {
                Ok(result) => result,
                Err(_) => return self.unavailable_record("record_reserved", &dimensions),
            };
            let (window, flags) = match result.split_last() {
                Some((window, flags)) if flags.len() == dimensions.len() => (*window, flags),
                _ => return self.unavailable_record("record_reserved", &dimensions),
            };
            FAILURE_RECORDS.fetch_add(dimensions.len() as u64, Ordering::Relaxed);
            let reached = dimensions
                .iter()
                .zip(flags.iter().copied())
                .filter_map(|((dimension, value), flag)| {
                    if flag == 1 {
                        Self::log_limit(*dimension, value, window);
                        Some(*dimension)
                    } else {
                        None
                    }
                })
                .collect();
            Ok(FailureRecord { reached })
        })
    }

    fn release<'a>(&'a self, dimensions: Vec<LimiterDimension>) -> LimiterFuture<'a, ()> {
        Box::pin(async move {
            if dimensions.is_empty() {
                return Ok(());
            }
            let limits = self.current_limits().await?;
            let mut connection = match self.client.get_multiplexed_async_connection().await {
                Ok(connection) => connection,
                Err(_) => {
                    self.log_storage_error("release", &dimensions);
                    return match self.failure_policy {
                        AuthLimiterFailurePolicy::FailOpen => Ok(()),
                        AuthLimiterFailurePolicy::FailClosed => Err(AuthLimiterError::Storage),
                    };
                }
            };
            let script = Script::new(RELEASE_ATTEMPT_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for (dimension, value) in &dimensions {
                invocation.key(Self::base_pending_key(*dimension, value));
            }
            invocation.arg(limits.window());
            let result: Result<i64, _> = invocation.invoke_async(&mut connection).await;
            if result.is_err() {
                self.log_storage_error("release", &dimensions);
                if matches!(self.failure_policy, AuthLimiterFailurePolicy::FailClosed) {
                    return Err(AuthLimiterError::Storage);
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "redis_tests.rs"]
mod tests;
