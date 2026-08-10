//! `refresh_store` 的纯函数单测。
//!
//! 拆成独立文件而不是内联 `mod tests`：墓碑分类的注释密度较高，内联后
//! `refresh_store.rs` 会越过 500 行的源文件门槛。

use super::{Tombstone, TombstoneState};
use time::{Duration, OffsetDateTime};

/// 升级前写入的墓碑没有 `state` / `recorded_at`：必须默认为 `Consumed`，
/// 且因为 `recorded_at` 缺省为 0 而落在并发窗口之外（按 replay 处理）。
#[test]
fn legacy_tombstones_default_to_an_old_consumption() {
    let tombstone: Tombstone =
        serde_json::from_str(r#"{"family_id":"family","client_id":"client","user_id":"user"}"#)
            .expect("legacy tombstone should deserialize");

    assert_eq!(tombstone.state, TombstoneState::Consumed);
    assert_eq!(tombstone.recorded_at, 0);
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
    assert!(!tombstone.is_recent_consumption(now));
}

/// 只有 `Consumed` 能解释并发竞争；主动撤销和 family 撤销永远不是竞争。
#[test]
fn only_consumption_tombstones_can_explain_a_concurrent_rotation() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(10);
    let tombstone = |state| Tombstone {
        family_id: "family".to_owned(),
        client_id: "client".to_owned(),
        user_id: "user".to_owned(),
        state,
        recorded_at: now.unix_timestamp(),
    };

    assert!(tombstone(TombstoneState::Consumed).is_recent_consumption(now));
    assert!(!tombstone(TombstoneState::ExplicitRevoke).is_recent_consumption(now));
    assert!(!tombstone(TombstoneState::FamilyRevoked).is_recent_consumption(now));
}

/// 多实例时钟不保证单调：领先于本机 `now` 的墓碑仍属并发窗口，
/// 否则轻微时钟偏移就会把正常并发刷新判成 replay 并撤销 family。
#[test]
fn clock_skew_in_either_direction_stays_inside_the_grace_window() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(10);
    let tombstone = |recorded_at| Tombstone {
        family_id: "family".to_owned(),
        client_id: "client".to_owned(),
        user_id: "user".to_owned(),
        state: TombstoneState::Consumed,
        recorded_at,
    };
    let grace = super::REFRESH_ROTATION_CONCURRENCY_GRACE_SECONDS;

    assert!(tombstone(now.unix_timestamp() - grace).is_recent_consumption(now));
    assert!(tombstone(now.unix_timestamp() + grace).is_recent_consumption(now));
    assert!(!tombstone(now.unix_timestamp() - grace - 1).is_recent_consumption(now));
    assert!(!tombstone(i64::MIN).is_recent_consumption(now));
}
