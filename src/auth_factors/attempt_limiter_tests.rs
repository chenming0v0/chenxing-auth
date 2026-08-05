//! 单元测试：预留额度在限流后端故障时的补偿行为（#130）。
//!
//! 这里只测试 `commit_reserved_failure` 的补偿逻辑，不依赖真实 Redis 或数据库，
//! 因为这一层只涉及 `AuthFailureLimiter` trait 的调用顺序。

use std::sync::{Arc, Mutex};

use crate::auth_limiter::{
    AuthFailureLimiter, FailureDimension,
    domain::{AuthLimiterError, FailureRecord, LimiterFuture},
};

use super::commit_reserved_failure;

/// 记录收到的调用类型，`record_reserved_failures` 始终返回存储错误以模拟 Redis 故障。
struct FailingRecordLimiter {
    calls: Mutex<Vec<&'static str>>,
}

impl FailingRecordLimiter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

impl AuthFailureLimiter for FailingRecordLimiter {
    fn is_limited<'a>(
        &'a self,
        _dimension: FailureDimension,
        _value: &str,
    ) -> LimiterFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    fn record_failure<'a>(
        &'a self,
        _dimension: FailureDimension,
        _value: &str,
    ) -> LimiterFuture<'a, bool> {
        // 该路径在此测试不经过
        Box::pin(async { Ok(false) })
    }

    fn clear<'a>(&'a self, _dimension: FailureDimension, _value: &str) -> LimiterFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    // `record_reserved_failures` 模拟 Redis 存储故障
    fn record_reserved_failures<'a>(
        &'a self,
        _dimensions: Vec<crate::auth_limiter::LimiterDimension>,
    ) -> LimiterFuture<'a, FailureRecord> {
        self.calls.lock().unwrap().push("record");
        Box::pin(async { Err(AuthLimiterError::Storage) })
    }

    // `release` 成功，记录调用以便断言
    fn release<'a>(
        &'a self,
        _dimensions: Vec<crate::auth_limiter::LimiterDimension>,
    ) -> LimiterFuture<'a, ()> {
        self.calls.lock().unwrap().push("release");
        Box::pin(async { Ok(()) })
    }
}

/// `record_reserved_failures` 成功时不应调用 `release`。
struct SuccessLimiter {
    calls: Mutex<Vec<&'static str>>,
}

impl SuccessLimiter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

impl AuthFailureLimiter for SuccessLimiter {
    fn is_limited<'a>(
        &'a self,
        _dimension: FailureDimension,
        _value: &str,
    ) -> LimiterFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    fn record_failure<'a>(
        &'a self,
        _dimension: FailureDimension,
        _value: &str,
    ) -> LimiterFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    fn clear<'a>(&'a self, _dimension: FailureDimension, _value: &str) -> LimiterFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn record_reserved_failures<'a>(
        &'a self,
        _dimensions: Vec<crate::auth_limiter::LimiterDimension>,
    ) -> LimiterFuture<'a, FailureRecord> {
        self.calls.lock().unwrap().push("record");
        Box::pin(async {
            Ok(FailureRecord {
                reached: Vec::new(),
            })
        })
    }

    fn release<'a>(
        &'a self,
        _dimensions: Vec<crate::auth_limiter::LimiterDimension>,
    ) -> LimiterFuture<'a, ()> {
        self.calls.lock().unwrap().push("release");
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
// #130：record_reserved_failures 失败时必须先归还预留额度再传播错误
async fn record_failure_releases_reservation_on_storage_error() {
    let limiter = FailingRecordLimiter::new();
    let dimensions = vec![(FailureDimension::Account, "user@example.com".to_owned())];

    let result = commit_reserved_failure(limiter.as_ref(), dimensions).await;

    // 原始存储错误必须透传给调用方
    assert!(
        matches!(result, Err(AuthLimiterError::Storage)),
        "expected Storage error, got {result:?}"
    );

    // 归还操作必须在错误之后被调用，且顺序是：record 先，release 后
    let calls = limiter.calls();
    assert_eq!(
        calls,
        vec!["record", "release"],
        "release must follow the failed record call, got: {calls:?}"
    );
}

#[tokio::test]
// 正常路径：记录成功时不触发额外的归还调用
async fn record_failure_does_not_release_on_success() {
    let limiter = SuccessLimiter::new();
    let dimensions = vec![(FailureDimension::Account, "user@example.com".to_owned())];

    let result = commit_reserved_failure(limiter.as_ref(), dimensions).await;

    assert!(result.is_ok(), "expected Ok, got {result:?}");
    let calls = limiter.calls();
    assert_eq!(
        calls,
        vec!["record"],
        "no release call on success, got: {calls:?}"
    );
}
