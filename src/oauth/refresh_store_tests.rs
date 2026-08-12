//! `refresh_store` 的纯函数单测。
//!
//! 拆成独立文件而不是内联 `mod tests`：墓碑分类的注释密度较高，内联后
//! `refresh_store.rs` 会越过 500 行的源文件门槛。

use super::{RefreshTokenStore, Tombstone, TombstoneState};
use crate::clock::SharedClock;
use crate::oauth::refresh::{
    REFRESH_TOKEN_ABSOLUTE_TTL_DAYS, REFRESH_TOKEN_SLIDING_TTL_DAYS, RefreshToken,
};
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

// ── 固定时钟驱动的 TTL 边界（Issue #299）────────────────────────────────────
//
// 主键 TTL 是 `min(滑动剩余, 绝对剩余)`。以前这段判定读进程墙钟，只能靠
// "180 天后再跑一次"来验证绝对上限真的收紧了 TTL。注入固定时钟后，
// 两条上限的交叉点可以直接构造出来。

const ISSUED_AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

fn store_at(now: OffsetDateTime) -> RefreshTokenStore {
    // 地址故意不可用：这些用例只读 TTL 计算，不发任何 Redis 命令。
    // 一旦实现改成"先连接再算 TTL"，用例会以连接错误的形式暴露出来。
    RefreshTokenStore::new(redis::Client::open("redis://127.0.0.1:1").expect("unreachable Redis"))
        .with_clock(SharedClock::fixed(now))
}

fn sliding_window_seconds() -> u64 {
    (REFRESH_TOKEN_SLIDING_TTL_DAYS * 24 * 60 * 60) as u64
}

fn token_issued_at(now: OffsetDateTime) -> RefreshToken {
    RefreshToken::new_at(
        "cx_client".to_owned(),
        "7".to_owned(),
        vec!["openid".to_owned()],
        now,
    )
}

/// 刚签发的 token：TTL 由滑动窗口决定，绝对上限还远。
#[test]
fn fresh_token_ttl_follows_the_sliding_window() {
    let token = token_issued_at(ISSUED_AT);
    let ttl = store_at(ISSUED_AT).effective_ttl(&token);

    assert_eq!(ttl, sliding_window_seconds());
}

/// Issue #109 的核心：持续轮换会把 `expires_at` 一直往后推，但 TTL 必须被
/// 首次签发后 180 天的绝对截止夹住。固定时钟把「绝对上限反超滑动窗口」的那一刻
/// 直接构造出来，不需要等真实时间。
#[test]
fn ttl_is_clamped_by_the_absolute_deadline_near_expiry() {
    // 站在绝对截止前一天：此时滑动窗口（30 天）比绝对剩余（1 天）宽。
    let now = ISSUED_AT + Duration::days(REFRESH_TOKEN_ABSOLUTE_TTL_DAYS - 1);
    let rotated = token_issued_at(ISSUED_AT).rotate_at(vec!["openid".to_owned()], now);

    let ttl = store_at(now).effective_ttl(&rotated);

    assert_eq!(ttl, 24 * 60 * 60, "绝对截止必须收紧 TTL");
    assert!(ttl < sliding_window_seconds(), "滑动窗口不得越过绝对上限");
}

/// 越过绝对截止之后 TTL 收敛到 1 秒：键立刻自然消失，而不是给 Redis 传负数。
#[test]
fn ttl_collapses_to_one_second_past_the_absolute_deadline() {
    let past_deadline = ISSUED_AT + Duration::days(REFRESH_TOKEN_ABSOLUTE_TTL_DAYS + 1);
    let token = token_issued_at(ISSUED_AT);

    assert_eq!(store_at(past_deadline).effective_ttl(&token), 1);
}

/// 同一个 store、两个固定时钟：到期前后的判定差异不依赖真实等待。
///
/// 这是 Issue #299 验收标准里"refresh 的过期边界可测"的直接体现。
#[test]
fn validation_flips_exactly_at_the_sliding_deadline() {
    let token = token_issued_at(ISSUED_AT);
    let deadline = token.expires_at;

    let before = SharedClock::fixed(deadline - Duration::seconds(1));
    let at = SharedClock::fixed(deadline);

    assert!(token.is_valid_for("cx_client", before.now()));
    assert!(!token.is_valid_for("cx_client", at.now()));
}
