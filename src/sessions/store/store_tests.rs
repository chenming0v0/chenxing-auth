//! `SessionStore` 的纯判定单测。
//!
//! - Issue #274：`save_authenticated` 在缺少 epoch 校验能力时必须拒绝签发。
//! - Issue #299：TTL 与活跃判定由注入的固定时钟驱动，不依赖真实等待。

use std::time::Duration;

use time::{Duration as TimeDuration, OffsetDateTime};

use super::{SessionEpochBinding, SessionStore, SessionStoreError};
use crate::{clock::SharedClock, sessions::domain::Session};

fn unreachable_store() -> SessionStore {
    // 用例只验证 Redis I/O **之前**的判定，连接地址故意不可用：
    // 一旦实现改成"先发命令再检查",测试会以 Redis 错误的形式暴露出来。
    SessionStore::with_redis_key(
        redis::Client::open("redis://127.0.0.1:1").expect("unreachable Redis URL"),
        [0x11; 32],
    )
}

/// 纯 Redis 路径读不到 `users.session_epoch`，因此无法确认认证依据是否仍然有效。
///
/// 这种情况必须拒绝签发，而不是把"无法校验"当成"校验通过"降级处理：
/// 后者会让一条本应被拒的凭据在配置退化时静默生效。
#[tokio::test]
async fn authenticated_save_is_refused_without_metadata() {
    let store = unreachable_store();
    let ttl = Duration::from_secs(60);
    let mut session = Session::new_with_idle_timeout("7".to_owned(), ttl, ttl).expect("session");

    let error = store
        .save_authenticated(&mut session, ttl, 0)
        .await
        .expect_err("epoch binding requires metadata");

    assert!(
        matches!(error, SessionStoreError::MetadataUnavailable),
        "expected the metadata requirement to reject the write, got {error}"
    );
}

/// Issue #646: binding session authentication to a user role requires the
/// Postgres user row. Missing metadata must not invent a role or reopen a
/// later `find_profile` TOCTOU.
#[tokio::test]
async fn authenticated_lookup_is_refused_without_metadata() {
    let store = unreachable_store();
    let error = store
        .find_authenticated("any-token")
        .await
        .expect_err("role binding requires metadata");
    assert!(
        matches!(error, SessionStoreError::MetadataUnavailable),
        "expected the metadata requirement to reject the lookup, got {error}"
    );
}

/// 绑定语义是两类登录来源，不是同一件事的强弱版本：`Current` 不携带任何期望值。
#[test]
fn epoch_binding_distinguishes_current_from_authenticated() {
    assert_ne!(
        SessionEpochBinding::Current,
        SessionEpochBinding::Authenticated(0)
    );
    assert_eq!(
        SessionEpochBinding::Authenticated(3),
        SessionEpochBinding::Authenticated(3)
    );
    assert_ne!(
        SessionEpochBinding::Authenticated(3),
        SessionEpochBinding::Authenticated(4)
    );
}

// ── 固定时钟驱动的 Session TTL 边界（Issue #299）──────────────────────────
//
// `redis_ttl_seconds` 是会话键在 Redis 的存活秒数，取
// `min(绝对剩余, idle 剩余, 传入 TTL, 撤销水位 TTL)`。以前这段判定读进程墙钟，
// 想验证"idle 截止先于绝对过期"只能真的等 30 分钟。注入固定时钟后，
// 两条上限的交叉点可以直接构造。

/// 会话创建时刻。固定值让所有剩余秒数都能手算。
const CREATED_AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

fn store_at(now: OffsetDateTime) -> SessionStore {
    unreachable_store().with_clock(SharedClock::fixed(now))
}

fn session_at(now: OffsetDateTime, ttl: Duration, idle_timeout: Duration) -> Session {
    Session::new_at_with_idle_timeout("7".to_owned(), ttl, idle_timeout, now).expect("session")
}

/// idle 窗口比绝对有效期短时，TTL 由 idle 截止决定。
#[test]
fn redis_ttl_follows_the_idle_deadline_when_it_is_nearer() {
    let absolute = Duration::from_secs(3_600);
    let idle = Duration::from_secs(600);
    // `new_at_with_idle_timeout` 把签发时的 idle 写进会话；查找用这个值，
    // 不再被 store 启动策略覆盖（#644）。
    let session = session_at(CREATED_AT, absolute, idle);
    let store = store_at(CREATED_AT).with_absolute_ttl(absolute);

    assert_eq!(
        store.redis_ttl_seconds(&session, absolute, store.clock.now()),
        600
    );
}

/// 时钟推进后剩余秒数随之收缩：这是"不依赖真实等待即可测到期前后"的直接体现。
#[test]
fn redis_ttl_shrinks_as_the_injected_clock_advances() {
    let absolute = Duration::from_secs(3_600);
    let idle = Duration::from_secs(3_600);
    let session = session_at(CREATED_AT, absolute, idle);

    for elapsed in [0_i64, 1_000, 3_599] {
        let now = CREATED_AT + TimeDuration::seconds(elapsed);
        let store = store_at(now).with_absolute_ttl(absolute);
        assert_eq!(
            store.redis_ttl_seconds(&session, absolute, store.clock.now()),
            (3_600 - elapsed) as u64,
            "elapsed {elapsed}s"
        );
    }
}

/// 到期之后 TTL 收敛到 1 秒，不会给 Redis 传 0 或负数。
#[test]
fn redis_ttl_collapses_to_one_second_past_absolute_expiry() {
    let absolute = Duration::from_secs(60);
    let session = session_at(CREATED_AT, absolute, absolute);
    let past = CREATED_AT + TimeDuration::seconds(120);
    let store = store_at(past).with_absolute_ttl(absolute);

    assert_eq!(
        store.redis_ttl_seconds(&session, absolute, store.clock.now()),
        1
    );
}

/// Session 的活跃判定在绝对过期时刻翻转：`expires_at` 是排他上界。
#[test]
fn session_activity_flips_exactly_at_absolute_expiry() {
    let absolute = Duration::from_secs(60);
    let session = session_at(CREATED_AT, absolute, absolute);
    let deadline = session.expires_at;

    let before = SharedClock::fixed(deadline - TimeDuration::seconds(1));
    assert!(session.is_active_at(before.now()));
    assert!(!session.is_active_at(SharedClock::fixed(deadline).now()));
}

/// 会话自己的 idle 窗口决定 Redis TTL，store 启动策略缩短之后也不能改写已签发会话。
#[test]
fn redis_ttl_follows_the_session_idle_not_the_store_policy() {
    let absolute = Duration::from_secs(3_600);
    let issued_idle = Duration::from_secs(1_800);
    let session = session_at(CREATED_AT, absolute, issued_idle);
    let store = store_at(CREATED_AT)
        .with_absolute_ttl(absolute)
        .with_session_policy(Duration::from_secs(60), 5);

    assert_eq!(
        store.redis_ttl_seconds(&session, absolute, store.clock.now()),
        1_800
    );
}

/// idle 超时同样在截止时刻翻转，且早于绝对过期。
#[test]
fn session_activity_flips_exactly_at_the_idle_deadline() {
    let absolute = Duration::from_secs(3_600);
    let idle = Duration::from_secs(600);
    let session = session_at(CREATED_AT, absolute, idle);
    let idle_deadline = CREATED_AT + TimeDuration::seconds(600);

    let before = SharedClock::fixed(idle_deadline - TimeDuration::seconds(1));
    assert!(session.is_active_at(before.now()));
    assert!(
        !session.is_active_at(SharedClock::fixed(idle_deadline).now()),
        "idle 截止必须先于绝对过期让会话失效"
    );
    assert!(idle_deadline < session.expires_at);
}

/// #644：查找不得把启动期 store policy 盖到已签发会话上。
#[test]
fn lookup_paths_do_not_overwrite_issuance_idle_with_store_policy() {
    let find = include_str!("postgres_find.rs");
    let redis = include_str!("redis_only.rs");
    assert!(
        find.contains("row.idle_timeout"),
        "PostgreSQL lookup must use the session row, not the boot-time store policy"
    );
    assert!(
        redis.contains("into_session_with_legacy_idle_fallback"),
        "Redis-only lookup must use the payload and an explicit legacy fallback"
    );
    assert_eq!(
        redis
            .matches("into_session_with_legacy_idle_fallback")
            .count(),
        4,
        "token/hash lookup and both concurrent rereads must share the fallback rule"
    );
    assert!(
        !find.contains("current_idle_timeout") && !redis.contains("current_idle_timeout"),
        "lookup paths must not apply the current runtime policy to persisted sessions"
    );
}
