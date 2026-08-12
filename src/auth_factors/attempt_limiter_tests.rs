//! 单元测试：预留额度在限流后端故障时的补偿行为（#130）。
//!
//! 这里只测试 `commit_reserved_failure` 的补偿逻辑，不依赖真实 Redis 或数据库，
//! 因为这一层只涉及 `AuthFailureLimiter` trait 的调用顺序。

use std::sync::{Arc, Mutex};

use crate::auth_limiter::{
    AuthFailureLimiter, FailureDimension,
    domain::{AuthLimiterError, FailureRecord, LimiterFuture, commit_reserved_failure},
};

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
    record: FailureRecord,
}

impl SuccessLimiter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            record: FailureRecord::recorded(Vec::new()),
        })
    }

    fn not_recorded() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            record: FailureRecord::not_recorded(),
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
        let record = self.record.clone();
        Box::pin(async move { Ok(record) })
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

#[tokio::test]
// #186：FailOpen 的未记账成功结果也必须归还 pending reservation。
async fn unrecorded_fail_open_result_releases_reservation() {
    let limiter = SuccessLimiter::not_recorded();
    let dimensions = vec![(FailureDimension::Account, "user@example.com".to_owned())];

    let result = commit_reserved_failure(limiter.as_ref(), dimensions).await;

    let record = result.expect("expected fail-open fallback record");
    assert!(!record.was_recorded());
    assert_eq!(limiter.calls(), vec!["record", "release"]);
}

#[tokio::test]
// #258：kid 退役不是一次用户失败，绝不能记账。
//
// 记账会让一个纯粹的运维动作把用户从「TOTP 不可用」推进到「账号被限流」，
// 于是连不带验证码的密码登录也被挡住。这里断言调用序列里只有 release。
async fn retired_key_releases_reservation_without_recording_a_failure() {
    let limiter = SuccessLimiter::new();
    let dimensions = vec![
        (FailureDimension::Account, "user@example.com".to_owned()),
        (FailureDimension::SourceIp, "203.0.113.7".to_owned()),
    ];

    super::release_key_unavailable(limiter.as_ref(), dimensions).await;

    assert_eq!(
        limiter.calls(),
        vec!["release"],
        "an unavailable key must never consume failure quota"
    );
}

#[tokio::test]
// #340：账号没有 TOTP 因子不是一次用户失败，绝不能记账。
//
// 因子缺失是服务端状态与客户端认知的错位（管理员重置/删除后的陈旧提交、或
// 因子列表读取与删除之间的竞态），不是用户输错码。记账会烧掉与密码失败共用
// 的账号额度，10 次后连密码登录也被锁 15 分钟。这里断言调用序列里只有 release。
async fn missing_factor_releases_reservation_without_recording_a_failure() {
    let limiter = SuccessLimiter::new();
    let dimensions = vec![
        (FailureDimension::Account, "user@example.com".to_owned()),
        (FailureDimension::SourceIp, "203.0.113.7".to_owned()),
    ];

    super::release_factor_missing(limiter.as_ref(), dimensions).await;

    assert_eq!(
        limiter.calls(),
        vec!["release"],
        "a missing factor must never consume failure quota"
    );
}
