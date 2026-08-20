//! 单元测试：KeyMaterial 安全语义与 prune_materials 逻辑。
//!
//! 内存清零本身无法在安全 Rust 里直接断言（drop 之后不允许读已释放内存），
//! 因此这里验证可观测的部分：
//! 1. Debug 输出不泄漏私钥字节（防止私钥进日志）
//! 2. prune_materials 保留窗口行为（含 #316 时钟偏差容忍值）

use std::collections::BTreeMap;
use std::time::Duration;

use time::{Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroizing;

use super::material::recovery_signing_key_id;
use super::{KeyMaterial, key_material, newest_key_id, prune};

const TEST_NOW_UNIX_SECONDS: i64 = 1_700_000_000;

fn test_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(TEST_NOW_UNIX_SECONDS).expect("valid test timestamp")
}

/// 构造指定“年龄”的在役材料。在役 key 不受保留窗口约束，年龄只影响身份判断。
fn aged(byte: u8, age_seconds: u64) -> KeyMaterial {
    let created_at = test_now() - TimeDuration::seconds(age_seconds as i64);
    key_material(Zeroizing::new(vec![byte]), created_at)
}

/// 构造一份已退役材料：`retired_seconds_ago` 前停止签发。
///
/// 创建时刻刻意设得远早于退役时刻（早一年），以证明裁剪只看退役时刻——按创建
/// 时刻起算的旧实现会把这些材料全部误判为过期（Issue #298）。
fn retired(byte: u8, retired_seconds_ago: u64) -> KeyMaterial {
    let retired_at = test_now() - TimeDuration::seconds(retired_seconds_ago as i64);
    let mut material = key_material(
        Zeroizing::new(vec![byte]),
        retired_at - TimeDuration::days(365),
    );
    material.retired_at = Some(retired_at);
    material
}

/// 替代者选择按退役时刻排定：mtime 最新（模拟 `touch` 或崩溃遗留孤儿）的旧 key
/// 不会胜出，最近退役的 key 才是“最近在役”的那个（Issue #318）。
#[test]
fn newest_key_id_ignores_creation_time_when_retirement_instants_differ() {
    let now = test_now();
    let mut touched = key_material(Zeroizing::new(vec![1]), now - TimeDuration::seconds(1));
    touched.retired_at = Some(now - TimeDuration::seconds(3600));
    let mut recently_retired =
        key_material(Zeroizing::new(vec![2]), now - TimeDuration::seconds(600));
    recently_retired.retired_at = Some(now - TimeDuration::seconds(60));
    let mut materials = BTreeMap::new();
    materials.insert("cx-touched".to_owned(), touched);
    materials.insert("cx-recent".to_owned(), recently_retired);

    assert_eq!(newest_key_id(&materials).as_deref(), Some("cx-recent"));
}

/// 从未退役（记录缺失）的 key 视为最新：它是最近还在役的那个。
#[test]
fn newest_key_id_prefers_a_never_retired_key_over_any_retired_one() {
    let mut materials = BTreeMap::new();
    materials.insert("cx-retired".to_owned(), retired(1, 1));
    materials.insert("cx-never".to_owned(), aged(2, 1));

    assert_eq!(newest_key_id(&materials).as_deref(), Some("cx-never"));
}

/// 退役时刻相同时退回创建时刻，保证次序确定。
#[test]
fn newest_key_id_falls_back_to_creation_time_for_an_equal_retirement_instant() {
    let now = test_now();
    let mut older = key_material(Zeroizing::new(vec![1]), now - TimeDuration::seconds(600));
    older.retired_at = Some(now - TimeDuration::seconds(60));
    let mut newer = key_material(Zeroizing::new(vec![2]), now - TimeDuration::seconds(1));
    newer.retired_at = Some(now - TimeDuration::seconds(60));
    let mut materials = BTreeMap::new();
    materials.insert("cx-older".to_owned(), older);
    materials.insert("cx-newer".to_owned(), newer);

    assert_eq!(newest_key_id(&materials).as_deref(), Some("cx-newer"));
}

/// 缺指针时必须保住上一把在役 key：pending 密钥从未退役、创建更晚，
/// 按 newest 会提前接管签发（Issue #655）。
#[test]
fn recovery_signing_key_id_prefers_the_last_active_over_a_pending_key() {
    let now = test_now();
    let previous = key_material(Zeroizing::new(vec![1]), now - TimeDuration::seconds(60));
    let pending = key_material(Zeroizing::new(vec![2]), now);
    let mut materials = BTreeMap::new();
    materials.insert("cx-previous".to_owned(), previous);
    materials.insert("cx-pending".to_owned(), pending);

    assert_eq!(
        newest_key_id(&materials).as_deref(),
        Some("cx-pending"),
        "the naive recency pick is exactly the early-activation bug"
    );
    assert_eq!(
        recovery_signing_key_id(&materials, Some("cx-previous"), Some("cx-pending")).as_deref(),
        Some("cx-previous")
    );
}

#[test]
fn recovery_signing_key_id_adopts_a_due_pending_key() {
    let now = test_now();
    let previous = key_material(Zeroizing::new(vec![1]), now - TimeDuration::seconds(60));
    let pending = key_material(Zeroizing::new(vec![2]), now);
    let mut materials = BTreeMap::new();
    materials.insert("cx-previous".to_owned(), previous);
    materials.insert("cx-pending".to_owned(), pending);

    assert_eq!(
        recovery_signing_key_id(&materials, Some("cx-pending"), None).as_deref(),
        Some("cx-pending")
    );
}

#[test]
fn recovery_signing_key_id_does_not_fall_back_to_an_excluded_pending_key() {
    let now = test_now();
    let mut materials = BTreeMap::new();
    materials.insert(
        "cx-pending".to_owned(),
        key_material(Zeroizing::new(vec![2]), now),
    );

    assert_eq!(
        recovery_signing_key_id(&materials, Some("cx-previous"), Some("cx-pending")),
        None,
        "fail closed: never persist a not-due pending key as active"
    );
}

/// 无跨实例时钟偏差的裁剪调用（单实例/内存模式语义）。
fn prune(
    active: &str,
    map: &mut BTreeMap<String, KeyMaterial>,
    retention: Duration,
) -> Vec<String> {
    prune::prune_materials(active, map, retention, Duration::ZERO, test_now())
}

#[test]
fn key_material_debug_redacts_private_key_bytes() {
    // 0xDE 的十进制是 222。Vec<u8> 默认 Debug 会把字节打成十进制整数列表，
    // 所以一旦 der 被原样输出，"222" 必然出现在结果里。
    let der = Zeroizing::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let material = key_material(der, OffsetDateTime::UNIX_EPOCH);

    let output = format!("{material:?}");

    assert!(
        output.contains("<redacted>"),
        "der must be redacted: {output}"
    );
    assert!(!output.contains("222"), "byte 0xDE leaked: {output}");
}

/// Issue #285：内存模式过去完全跳过裁剪，JWKS 随轮换次数无界增长。
/// 保留窗口是协议约束，与材料落在磁盘上还是只在内存里无关。
#[test]
fn prune_materials_applies_retention_without_a_directory() {
    let active = "cx-active".to_owned();
    let expired = "cx-expired".to_owned();
    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(1, 0));
    map.insert(expired.clone(), retired(2, 999_999));

    prune(&active, &mut map, Duration::from_secs(1));

    assert!(map.contains_key(&active), "active key must survive");
    assert!(
        !map.contains_key(&expired),
        "in-memory manager must prune expired keys too"
    );
}

#[test]
fn prune_materials_retains_active_and_recent_removes_expired() {
    let active = "cx-active".to_owned();
    let recent = "cx-recent".to_owned();
    let expired = "cx-expired".to_owned();
    let retention = Duration::from_secs(3600);

    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(1, 0));
    map.insert(recent.clone(), retired(2, 60));
    map.insert(expired.clone(), retired(3, 7200));

    prune(&active, &mut map, retention);

    assert!(map.contains_key(&active), "active key must survive");
    assert!(map.contains_key(&recent), "recent key must survive");
    assert!(!map.contains_key(&expired), "expired key must be pruned");
}

#[test]
fn prune_materials_never_removes_active_key_even_if_stale() {
    // 活跃密钥是当前签名密钥，无论多旧都必须保留，否则签名链路直接断掉。
    let active = "cx-stale".to_owned();
    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(9, 999_999));

    prune(&active, &mut map, Duration::from_secs(60));

    assert!(map.contains_key(&active), "active key always retained");
}

/// 边界：保留窗口是左闭右开的 `[retired_at, retired_at + retention)`。
///
/// 右端点排他是安全的：令牌最迟在退役那一刻签发，`exp` 不晚于
/// `retired_at + max_token_ttl`，而配置校验保证 `retention >= max_token_ttl`。
#[test]
fn prune_materials_keeps_a_key_until_its_retirement_window_closes() {
    let active = "cx-active".to_owned();
    let inside = "cx-inside".to_owned();
    let boundary = "cx-boundary".to_owned();
    let retention = Duration::from_secs(600);

    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(1, 0));
    map.insert(inside.clone(), retired(2, 599));
    map.insert(boundary.clone(), retired(3, 600));

    prune(&active, &mut map, retention);

    assert!(map.contains_key(&inside), "窗口尚未走完必须保留");
    assert!(!map.contains_key(&boundary), "窗口右端点排他");
}

/// Issue #316 的核心回归：快钟实例不得提前裁剪仍处保留窗口的共享密钥。
///
/// 退役实例的时钟比本实例慢 300 秒：本实例看到 elapsed = retention（按旧实现已
/// 过期），但真实只过了 retention - 300，公钥仍被其他实例用于验签。容忍值必须
/// 让这个 key 继续保留。
#[test]
fn prune_materials_with_skew_allowance_keeps_keys_a_fast_clock_would_drop() {
    let active = "cx-active".to_owned();
    let retired_by_slow_instance = "cx-retired-by-slow-clock".to_owned();
    let retention = Duration::from_secs(600);
    let skew_allowance = Duration::from_secs(300);

    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(1, 0));
    map.insert(retired_by_slow_instance.clone(), retired(2, 600));

    prune::prune_materials(&active, &mut map, retention, skew_allowance, test_now());

    assert!(
        map.contains_key(&retired_by_slow_instance),
        "快钟实例不得在真实窗口结束前裁剪共享密钥"
    );
}

/// 偏差超过容忍值后窗口才能关闭：保留期结束后旧私钥仍需回收，
/// 容忍值只是把关闭边界推迟，不能把回收变成永不发生。
#[test]
fn prune_materials_with_skew_allowance_removes_keys_beyond_window_plus_allowance() {
    let active = "cx-active".to_owned();
    let expired = "cx-expired".to_owned();
    let retention = Duration::from_secs(600);
    let skew_allowance = Duration::from_secs(300);

    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(1, 0));
    map.insert(expired.clone(), retired(2, 901));

    prune::prune_materials(&active, &mut map, retention, skew_allowance, test_now());

    assert!(
        !map.contains_key(&expired),
        "超过窗口加容忍值的 key 必须回收"
    );
}

/// Issue #298 的核心回归：长期在役的 key 退役后必须拿到一个完整的保留窗口。
///
/// 这个 key 创建于一年前、远超 retention，但它刚刚才退役。按创建时刻起算的旧实现
/// 会立刻删掉它，把它在最后一刻签发、尚未到 `exp` 的令牌一起作废。
#[test]
fn prune_materials_grants_a_long_lived_key_a_full_window_from_retirement() {
    let active = "cx-active".to_owned();
    let long_lived = "cx-long-lived".to_owned();
    let retention = Duration::from_secs(3600);

    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(1, 0));
    map.insert(long_lived.clone(), retired(2, 0));

    prune(&active, &mut map, retention);

    assert!(
        map.contains_key(&long_lived),
        "保留窗口必须从退役时刻起算，而不是创建时刻"
    );
}

/// 并发轮换各自在抢锁前捕获 now，后执行者可能持有更早的快照：晚于参照时刻
/// 退役的 key 不可能已过期，必须保留，否则会删掉仍在 JWKS 里公布的公钥。
#[test]
fn prune_materials_keeps_keys_retired_after_the_reference_instant() {
    let active = "cx-active".to_owned();
    let future = "cx-future".to_owned();
    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(1, 0));
    let mut future_material = key_material(Zeroizing::new(vec![2]), test_now());
    future_material.retired_at = Some(test_now() + TimeDuration::hours(1));
    map.insert(future.clone(), future_material);

    prune(&active, &mut map, Duration::ZERO);

    assert!(map.contains_key(&future), "未来退役的 key 不得被裁剪");
}

/// 退役时刻必须单调：重复轮换或重复加载不能把窗口起点不断往后推，
/// 否则旧公钥永远不下线。
#[test]
fn mark_retired_keeps_the_first_retirement_instant() {
    let key_id = "cx-key".to_owned();
    let mut map = BTreeMap::new();
    map.insert(key_id.clone(), aged(1, 0));

    let first = prune::mark_retired(&mut map, &key_id, test_now()).expect("first retirement");
    let second = prune::mark_retired(&mut map, &key_id, test_now() + TimeDuration::hours(1))
        .expect("restamp");

    assert_eq!(first, test_now());
    assert_eq!(second, first, "退役时刻不得被后续调用推后");
    assert_eq!(map[&key_id].retired_at, Some(first));
}

/// 在役 key 不带退役时刻，因此不受保留窗口约束。
#[test]
fn prune_materials_returns_the_removed_key_ids() {
    let active = "cx-active".to_owned();
    let expired = "cx-expired".to_owned();
    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(1, 0));
    map.insert(expired.clone(), retired(2, 7200));

    let removed = prune(&active, &mut map, Duration::from_secs(60));

    assert_eq!(removed, vec![expired], "磁盘删除依赖这份返回值");
}

/// 零保留窗口下内存模式也必须只留 active key，JWKS 不随轮换增长。
#[test]
fn prune_materials_with_zero_retention_keeps_only_the_active_key() {
    let active = "cx-active".to_owned();
    let previous = "cx-previous".to_owned();
    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(1, 0));
    map.insert(previous.clone(), retired(2, 0));

    prune(&active, &mut map, Duration::ZERO);

    assert_eq!(map.len(), 1);
    assert!(map.contains_key(&active));
}
