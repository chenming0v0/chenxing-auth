//! 吊销提交流程的单元测试（Issue #315）。
//!
//! 覆盖：提交后收敛失败时发布计划快照、收敛结果与计划不一致时发布磁盘事实。

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use time::OffsetDateTime;

use super::revocation::{CommitOutcome, snapshot_after_commit};
use super::{build_key_state, generate_rsa_key, key_material};

const TEST_NOW_UNIX_SECONDS: i64 = 1_700_000_000;

fn test_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(TEST_NOW_UNIX_SECONDS).expect("valid test timestamp")
}

/// 吊销提交后立即收敛失败（`CommitOutcome::Pending`）时，内存必须切换到计划快照：
/// 被吊销的 key 不得继续作为 active 签发，否则本实例签出的 token 在其余已收敛的
/// 实例上会全部验不过（Issue #315）。
#[test]
fn committed_but_unconverged_revocation_publishes_the_planned_snapshot() {
    let now = test_now();
    let (revoked, _revoked_der) = generate_rsa_key().expect("revoked key");
    let (replacement, replacement_der) = generate_rsa_key().expect("replacement key");
    let retention = Duration::from_secs(3600);
    let planned_state = build_key_state(
        None,
        retention,
        Duration::ZERO,
        Duration::ZERO,
        replacement.clone(),
        BTreeMap::from([(replacement.clone(), key_material(replacement_der, now))]),
        None,
    )
    .expect("planned snapshot must be constructible");

    let (active_key_id, state) = snapshot_after_commit(
        Path::new("/unused"),
        retention,
        Duration::ZERO,
        &replacement,
        planned_state,
        CommitOutcome::Pending,
    )
    .expect("a committed revocation must publish even when convergence is pending");

    assert_eq!(active_key_id, replacement);
    assert_eq!(state.active_key_id, replacement);
    assert!(
        !state.private_materials.contains_key(&revoked),
        "the revoked key must leave the in-memory snapshot at the commit point"
    );
    assert!(
        !state.verification_keys.contains_key(&revoked),
        "the revoked key must not stay published for verification"
    );
}

/// 磁盘收敛结果与计划快照不一致（异常恢复选择了替代 active）时，发布磁盘读回的
/// 实际快照，而不是调用前推算的计划快照。
#[test]
fn converged_revocation_publishes_the_actual_disk_snapshot() {
    let now = test_now();
    let (replacement, replacement_der) = generate_rsa_key().expect("replacement key");
    let (fallback, fallback_der) = generate_rsa_key().expect("fallback key");
    let retention = Duration::from_secs(3600);
    let planned_state = build_key_state(
        None,
        retention,
        Duration::ZERO,
        Duration::ZERO,
        replacement.clone(),
        BTreeMap::from([(replacement.clone(), key_material(replacement_der, now))]),
        None,
    )
    .expect("planned snapshot must be constructible");
    let disk_materials = BTreeMap::from([(fallback.clone(), key_material(fallback_der, now))]);

    let (active_key_id, state) = snapshot_after_commit(
        Path::new("/unused"),
        retention,
        Duration::ZERO,
        &replacement,
        planned_state,
        CommitOutcome::Converged(fallback.clone(), disk_materials),
    )
    .expect("converged commit must publish the disk snapshot");

    assert_eq!(active_key_id, fallback);
    assert_eq!(state.active_key_id, fallback);
    assert!(state.private_materials.contains_key(&fallback));
    assert!(
        !state.private_materials.contains_key(&replacement),
        "the planned snapshot must not override the converged disk facts"
    );
}
