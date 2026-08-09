//! [`SessionOutboxPolicy`] 与 [`OutboxCleanup`] 的纯函数测试。
//!
//! 这些用例不连数据库：它们守的是策略取值的收敛规则和积压判定，而这两者一旦
//! 出错，症状是"清理静默不删"或"事件在第一次投递前就被判死"——都不会报错，只会
//! 在生产表大小和会话行为上体现出来。

use super::*;

#[test]
fn policy_defaults_keep_dead_letters_longer_than_processed_events() {
    let policy = SessionOutboxPolicy::default();
    assert!(policy.dead_letter_retention > policy.processed_retention);
    assert_eq!(
        policy,
        policy.sanitized(),
        "defaults must already be inside the usable range"
    );
}

#[test]
fn sanitizing_rejects_a_zero_batch_and_a_zero_attempt_budget() {
    let policy = SessionOutboxPolicy {
        processed_retention: Duration::ZERO,
        dead_letter_retention: Duration::ZERO,
        cleanup_batch: 0,
        cleanup_interval: Duration::ZERO,
        max_attempts: 0,
    }
    .sanitized();
    assert_eq!(
        policy.cleanup_batch, 1,
        "a zero batch would make cleanup a no-op loop"
    );
    assert_eq!(
        policy.max_attempts, 1,
        "a zero budget would dead-letter every event before its first delivery"
    );
    assert_eq!(policy.processed_retention, Duration::from_secs(1));
    assert_eq!(policy.dead_letter_retention, Duration::from_secs(1));
    assert_eq!(policy.cleanup_interval, Duration::from_secs(1));
}

#[test]
fn sanitizing_caps_retention_so_the_sql_interval_cannot_overflow() {
    let policy = SessionOutboxPolicy {
        processed_retention: Duration::MAX,
        dead_letter_retention: Duration::MAX,
        cleanup_batch: u32::MAX,
        ..SessionOutboxPolicy::default()
    }
    .sanitized();
    assert_eq!(policy.processed_retention, MAX_RETENTION);
    assert_eq!(policy.dead_letter_retention, MAX_RETENTION);
    assert_eq!(policy.cleanup_batch, MAX_CLEANUP_BATCH);
    assert!(policy.processed_retention_interval() > time::Duration::ZERO);
    assert!(policy.dead_letter_retention_interval() > time::Duration::ZERO);
    assert_eq!(policy.cleanup_limit(), i64::from(MAX_CLEANUP_BATCH));
}

#[test]
fn saturation_is_measured_per_terminal_class() {
    let batch = 5;
    assert!(
        !OutboxCleanup {
            processed: 4,
            dead_lettered: 4,
        }
        .is_saturated(batch),
        "neither class filled the batch, so there is no backlog to chase"
    );
    assert!(
        OutboxCleanup {
            processed: 5,
            dead_lettered: 0,
        }
        .is_saturated(batch)
    );
    assert!(
        OutboxCleanup {
            processed: 0,
            dead_lettered: 5,
        }
        .is_saturated(batch)
    );
    assert_eq!(
        OutboxCleanup {
            processed: 2,
            dead_lettered: 3,
        }
        .total(),
        5
    );
}
