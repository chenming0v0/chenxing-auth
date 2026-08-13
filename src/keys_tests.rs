//! 单元测试：KeyMaterial 安全语义与 prune_materials 逻辑。
//!
//! 内存清零本身无法在安全 Rust 里直接断言（drop 之后不允许读已释放内存），
//! 因此这里验证可观测的部分：
//! 1. Debug 输出不泄漏私钥字节（防止私钥进日志）
//! 2. Zeroizing 包装后签名与公钥派生功能正常（功能未破坏）
//! 3. prune_materials 保留窗口行为不变
//! 4. JWKS 响应不含 RSA 私钥参数

use std::collections::BTreeMap;
use std::time::Duration;

use time::{Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::oauth::token::{decode_access_token, issue_access_token};

use super::keys_material::retirement_window_open_at;
use super::{
    DEFAULT_KEY_RETENTION_SECONDS, KeyManager, KeyMaterial, KeySyncOutcome,
    MINIMUM_KEY_SYNC_INTERVAL, key_material, mark_retired, newest_key_id, prune_materials,
};

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

    prune_materials(&active, &mut map, Duration::from_secs(1), test_now());

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

    prune_materials(&active, &mut map, retention, test_now());

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

    prune_materials(&active, &mut map, Duration::from_secs(60), test_now());

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

    prune_materials(&active, &mut map, retention, test_now());

    assert!(map.contains_key(&inside), "窗口尚未走完必须保留");
    assert!(!map.contains_key(&boundary), "窗口右端点排他");
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

    prune_materials(&active, &mut map, retention, test_now());

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

    prune_materials(&active, &mut map, Duration::ZERO, test_now());

    assert!(map.contains_key(&future), "未来退役的 key 不得被裁剪");
}

/// 退役时刻必须单调：重复轮换或重复加载不能把窗口起点不断往后推，
/// 否则旧公钥永远不下线。
#[test]
fn mark_retired_keeps_the_first_retirement_instant() {
    let key_id = "cx-key".to_owned();
    let mut map = BTreeMap::new();
    map.insert(key_id.clone(), aged(1, 0));

    let first = mark_retired(&mut map, &key_id, test_now()).expect("first retirement");
    let second =
        mark_retired(&mut map, &key_id, test_now() + TimeDuration::hours(1)).expect("restamp");

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

    let removed = prune_materials(&active, &mut map, Duration::from_secs(60), test_now());

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

    prune_materials(&active, &mut map, Duration::ZERO, test_now());

    assert_eq!(map.len(), 1);
    assert!(map.contains_key(&active));
}

/// 内存模式的 JWKS 必须有界（Issue #285），同时每个退役 key 都要拿到完整窗口
/// （Issue #298）：稳态下发布集合是“active + 仍在窗口内的已退役 key”。
#[tokio::test]
async fn in_memory_rotation_keeps_the_published_key_set_bounded() {
    let manager = KeyManager::generate().expect("key generation");
    let initial_key_id = manager.key_id();
    let retention = TimeDuration::seconds(DEFAULT_KEY_RETENTION_SECONDS as i64);
    let now = OffsetDateTime::now_utc();

    // 窗口内轮换：旧公钥继续发布，令牌验证不断。
    let within_window = manager
        .rotate_at(now + TimeDuration::seconds(1))
        .await
        .expect("rotation inside the retention window");
    assert_eq!(within_window.published_key_count, 2);
    assert!(manager.verification_key_for(&initial_key_id).is_some());

    // 跨过第一个 key 的保留窗口后再轮换：它下线，但刚退役的第二个 key 必须留下。
    // 余量取 60 秒，避开窗口右端点。
    let beyond_window = manager
        .rotate_at(now + retention + TimeDuration::seconds(60))
        .await
        .expect("rotation beyond the retention window");
    assert_eq!(
        beyond_window.published_key_count, 2,
        "JWKS must stay bounded at active + keys still inside their window"
    );
    assert_eq!(manager.jwks().keys.len(), 2);
    assert!(
        manager.verification_key_for(&initial_key_id).is_none(),
        "the first key's retirement window has closed"
    );
    assert!(
        manager
            .verification_key_for(&within_window.key_id)
            .is_some(),
        "a key that just retired keeps a full verification window (Issue #298)"
    );
    assert_eq!(manager.key_id(), beyond_window.key_id);
    assert!(
        manager
            .verification_key_for(&beyond_window.key_id)
            .is_some(),
        "active key must stay published"
    );
}

#[test]
fn retirement_window_open_at_handles_the_exact_expiry_boundary() {
    let now = test_now();
    let retention = Duration::from_secs(60);

    assert!(retirement_window_open_at(
        Some(now - TimeDuration::seconds(59)),
        retention,
        now
    ));
    assert!(
        !retirement_window_open_at(Some(now - TimeDuration::seconds(60)), retention, now),
        "窗口右端点排他"
    );
}

/// 尚未退役的 key 不受保留窗口约束：它仍在签发，删掉就直接断签名链路。
#[test]
fn retirement_window_open_at_never_closes_for_an_active_key() {
    assert!(retirement_window_open_at(None, Duration::ZERO, test_now()));
}

#[test]
fn zeroizing_der_preserves_signing_and_public_key_derivation() {
    // 功能验证：der 被 Zeroizing 包装后，签名密钥构建与 JWT 验证链路不受影响。
    // 注：drop 后内存是否真正被清零无法在安全 Rust 中断言，这里只覆盖功能正确性。
    let manager = KeyManager::generate().expect("key generation");
    let scopes = ["openid".to_owned()];

    let token = issue_access_token(
        &manager,
        "https://auth.test",
        "test-user",
        "test-client",
        &scopes,
        3600,
    )
    .expect("signing with Zeroizing-wrapped DER");

    let claims = decode_access_token(&manager, "https://auth.test", "test-client", &token)
        .expect("JWT validation after Zeroizing wrapping");

    assert_eq!(claims.sub, "test-user");
    assert_eq!(claims.aud, "test-client");
}

#[test]
fn jwks_never_exposes_rsa_private_parameters() {
    // JWKS 只应发布公开参数；RFC 7518 §6.3.2 的私钥参数绝不能出现在响应里。
    let manager = KeyManager::generate().expect("key generation");
    let json = serde_json::to_string(&manager.jwks()).expect("serialize");

    for name in ["d", "p", "q", "dp", "dq", "qi"] {
        let field = format!("\"{name}\":");
        assert!(!json.contains(&field), "JWKS leaked private {name}");
    }

    assert!(json.contains("\"n\":"), "JWKS must include modulus n");
    assert!(json.contains("\"e\":"), "JWKS must include exponent e");
}

/// 签发热路径取的是同一次读锁下的 `kid` 与私钥，且不做任何磁盘 IO（Issue #257）。
#[test]
fn active_signing_key_is_a_consistent_memory_snapshot() {
    let manager = KeyManager::generate().expect("key generation");
    let snapshot = manager.active_signing_key();

    assert_eq!(snapshot.key_id(), manager.key_id());
    assert!(
        manager.verification_key_for(snapshot.key_id()).is_some(),
        "active kid must be published for verification"
    );
}

/// 未发布的 `kid` 是协议结果，返回 `None`，不制造服务端错误。
#[test]
fn verification_key_for_unknown_key_id_returns_none() {
    let manager = KeyManager::generate().expect("key generation");

    assert!(manager.verification_key_for("cx-not-published").is_none());
}

/// 未知 `kid` 触发的提示必须是非阻塞的：没有 worker 在等时也不能挂住热路径。
#[test]
fn resync_hint_does_not_block_without_a_worker() {
    let manager = KeyManager::generate().expect("key generation");

    for _ in 0..1_000 {
        assert!(manager.verification_key_for("cx-not-published").is_none());
    }
}

/// 纯内存管理器没有共享目录，同步是明确的 no-op 而不是错误。
#[test]
fn in_memory_manager_sync_reports_not_persisted() {
    let manager = KeyManager::generate().expect("key generation");

    assert_eq!(
        manager.sync_from_disk_blocking().expect("in-memory sync"),
        KeySyncOutcome::NotPersisted
    );
}

/// 无共享目录时后台任务必须立即退出，而不是空转一个什么都不做的定时器。
///
/// 传入 1ns 间隔：如果实现真的进入了循环，它会被抬到 `MINIMUM_KEY_SYNC_INTERVAL`
/// 并持续 tick，从而撞上这里的超时。
#[tokio::test]
async fn disk_sync_worker_returns_immediately_without_a_key_directory() {
    let manager = KeyManager::generate().expect("key generation");

    tokio::time::timeout(
        MINIMUM_KEY_SYNC_INTERVAL,
        manager.run_disk_sync_worker(Duration::from_nanos(1)),
    )
    .await
    .expect("worker must not schedule ticks without a key directory");
}
