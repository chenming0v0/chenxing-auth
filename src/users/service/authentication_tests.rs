use std::sync::{Arc, Mutex, atomic::AtomicUsize};

use super::{UserService, UserServiceError};
use crate::auth_limiter::domain::{
    AuthLimiterError, AuthReservation, FailureRecord, LimiterDimension, LimiterFuture,
};
use crate::auth_limiter::{AuthFailureLimiter, FailureDimension};
use crate::users::domain::LoginInput;

struct AlwaysLimited;

#[derive(Default)]
struct CountingLimiter {
    calls: AtomicUsize,
}

impl CountingLimiter {
    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl AuthFailureLimiter for CountingLimiter {
    fn is_limited<'a>(
        &'a self,
        _dimension: FailureDimension,
        _value: &str,
    ) -> LimiterFuture<'a, bool> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Box::pin(async { Ok(false) })
    }

    fn record_failure<'a>(
        &'a self,
        _dimension: FailureDimension,
        _value: &str,
    ) -> LimiterFuture<'a, bool> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Box::pin(async { Ok(false) })
    }

    fn clear<'a>(&'a self, _dimension: FailureDimension, _value: &str) -> LimiterFuture<'a, ()> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Box::pin(async { Ok(()) })
    }
}

impl AuthFailureLimiter for AlwaysLimited {
    fn is_limited<'a>(
        &'a self,
        _dimension: FailureDimension,
        _value: &str,
    ) -> LimiterFuture<'a, bool> {
        Box::pin(async { Ok(true) })
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
}

struct FailingRecordLimiter {
    calls: Mutex<Vec<&'static str>>,
    released_dimensions: Mutex<Vec<LimiterDimension>>,
}

impl FailingRecordLimiter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            released_dimensions: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn released_dimensions(&self) -> Vec<LimiterDimension> {
        self.released_dimensions.lock().unwrap().clone()
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
        Box::pin(async { Ok(false) })
    }

    fn clear<'a>(&'a self, _dimension: FailureDimension, _value: &str) -> LimiterFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn record_reserved_failures<'a>(
        &'a self,
        _reservation: AuthReservation,
    ) -> LimiterFuture<'a, FailureRecord> {
        self.calls.lock().unwrap().push("record");
        Box::pin(async { Err(AuthLimiterError::Storage) })
    }

    fn release<'a>(&'a self, reservation: AuthReservation) -> LimiterFuture<'a, ()> {
        self.calls.lock().unwrap().push("release");
        self.released_dimensions
            .lock()
            .unwrap()
            .extend(reservation.dimensions());
        Box::pin(async { Err(AuthLimiterError::Storage) })
    }
}

fn lazy_pool() -> crate::sqlx::PgPool {
    crate::sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://invalid-host/unused")
        .expect("lazy pool")
}

#[tokio::test]
async fn invalid_login_input_is_rejected_before_limiter_or_database() {
    let limiter = Arc::new(CountingLimiter::default());
    let service = UserService::new(lazy_pool(), limiter.clone());
    let result = service
        .authenticate(
            LoginInput {
                identifier: "ab".to_owned(),
                password: "incorrect password".to_owned(),
                totp_code: None,
            },
            Some("127.0.0.1"),
        )
        .await;

    assert!(matches!(result, Err(UserServiceError::InvalidLoginInput)));
    assert_eq!(limiter.calls(), 0);
}

/// Issue #259：超长口令必须在限流预留与数据库查询之前被拒绝。
///
/// 断言 `limiter.calls() == 0` 是关键：它同时证明请求没有触达限流维度，
/// 也证明流程根本没走到 `find_credentials_by_identifier`（连接池指向不可用
/// 主机，一旦查询就会返回 `Database` 而不是 `InvalidLoginInput`）。
/// 由此推出超长明文也不会到达 Argon2——口令校验在这两步之后。
#[tokio::test]
async fn oversized_password_is_rejected_before_limiter_or_database() {
    let limiter = Arc::new(CountingLimiter::default());
    let service = UserService::new(lazy_pool(), limiter.clone());
    let result = service
        .authenticate(
            LoginInput {
                identifier: "user@example.com".to_owned(),
                password: "a".repeat(crate::users::credentials::MAX_PASSWORD_LENGTH + 1),
                totp_code: None,
            },
            Some("127.0.0.1"),
        )
        .await;

    assert!(matches!(result, Err(UserServiceError::InvalidLoginInput)));
    assert_eq!(limiter.calls(), 0);
}

/// 超长标识符同样不进入限流维度和 SQL 绑定参数（Issue #259）。
#[tokio::test]
async fn oversized_identifier_is_rejected_before_limiter_or_database() {
    let limiter = Arc::new(CountingLimiter::default());
    let service = UserService::new(lazy_pool(), limiter.clone());
    let local = "a".repeat(crate::users::domain::MAX_IDENTIFIER_LENGTH);
    let result = service
        .authenticate(
            LoginInput {
                identifier: format!("{local}@example.com"),
                password: "incorrect password".to_owned(),
                totp_code: None,
            },
            Some("127.0.0.1"),
        )
        .await;

    assert!(matches!(result, Err(UserServiceError::InvalidLoginInput)));
    assert_eq!(limiter.calls(), 0);
}

#[tokio::test]
async fn valid_login_input_still_uses_rate_limiter_before_database() {
    let service = UserService::new(lazy_pool(), Arc::new(AlwaysLimited));
    let result = service
        .authenticate(
            LoginInput {
                identifier: "user@example.com".to_owned(),
                password: "incorrect password".to_owned(),
                totp_code: None,
            },
            Some("127.0.0.1"),
        )
        .await;
    assert!(matches!(result, Err(UserServiceError::RateLimited)));
}

/// Skip + 无源 IP 时 IP 维度是空的。空预留是放行，不能当成「已达上限」
/// 把每次 oneshot 登录打成 401（ed3b70a 把 bool 改成 reservation 之后的歧义）。
#[tokio::test]
async fn missing_source_ip_skip_is_not_treated_as_rate_limited() {
    let service = UserService::new(lazy_pool(), Arc::new(AlwaysLimited));
    let result = service
        .authenticate(
            LoginInput {
                identifier: "user@example.com".to_owned(),
                password: "incorrect password".to_owned(),
                totp_code: None,
            },
            None,
        )
        .await;
    assert!(
        matches!(result, Err(UserServiceError::Database(_))),
        "empty IP reservation must reach the database, not RateLimited: {result:?}"
    );
}

#[tokio::test]
async fn record_failure_releases_all_dimensions_and_preserves_limiter_error() {
    let limiter = FailingRecordLimiter::new();
    let service = UserService::new(lazy_pool(), limiter.clone());
    let dimensions = vec![
        (FailureDimension::SourceIp, "192.0.2.1".to_owned()),
        (FailureDimension::Account, "user@example.com".to_owned()),
    ];
    let reservation = AuthReservation::single(dimensions.clone(), AuthReservation::token());

    let result = service.record_failure(reservation).await;

    assert!(matches!(
        result,
        Err(UserServiceError::Limiter(AuthLimiterError::Storage))
    ));
    assert_eq!(limiter.calls(), vec!["record", "release"]);
    assert_eq!(limiter.released_dimensions(), dimensions);
}

#[test]
fn empty_reservation_is_an_allow_not_a_denial() {
    let allowed = AuthReservation::single(Vec::new(), AuthReservation::token());
    assert!(allowed.is_empty());
    assert!(!allowed.is_denied());
    let denied = AuthReservation::denied();
    assert!(denied.is_empty());
    assert!(denied.is_denied());
}
