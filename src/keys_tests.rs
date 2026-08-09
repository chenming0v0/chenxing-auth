//! 单元测试：KeyMaterial 安全语义与 prune_materials 逻辑。
//!
//! 内存清零本身无法在安全 Rust 里直接断言（drop 之后不允许读已释放内存），
//! 因此这里验证可观测的部分：
//! 1. Debug 输出不泄漏私钥字节（防止私钥进日志）
//! 2. Zeroizing 包装后签名与公钥派生功能正常（功能未破坏）
//! 3. prune_materials 保留窗口行为不变
//! 4. JWKS 响应不含 RSA 私钥参数

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use time::{Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::oauth::token::{decode_access_token, issue_access_token};

use super::{
    KeyManager, KeyMaterial, KeySyncOutcome, MINIMUM_KEY_SYNC_INTERVAL, key_material,
    prune_materials, within_retention_at,
};

const TEST_NOW_UNIX_SECONDS: i64 = 1_700_000_000;

fn test_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(TEST_NOW_UNIX_SECONDS).expect("valid test timestamp")
}

/// 构造指定“年龄”的密钥材料，用于保留窗口测试。
fn aged(byte: u8, age_seconds: u64) -> KeyMaterial {
    let created_at = test_now() - TimeDuration::seconds(age_seconds as i64);
    key_material(Zeroizing::new(vec![byte]), created_at)
}

fn storage_dir() -> PathBuf {
    PathBuf::from("/tmp")
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

#[test]
fn prune_materials_is_noop_without_directory() {
    // 内存模式（无持久化目录）下不剪裁任何条目，即使条目已远超 retention。
    let key_id = "cx-test".to_owned();
    let mut map = BTreeMap::new();
    map.insert(key_id.clone(), aged(1, 999_999));

    prune_materials(None, &key_id, &mut map, Duration::from_secs(1), test_now());

    assert_eq!(map.len(), 1, "in-memory manager must not prune");
}

#[test]
fn prune_materials_retains_active_and_recent_removes_expired() {
    let active = "cx-active".to_owned();
    let recent = "cx-recent".to_owned();
    let expired = "cx-expired".to_owned();
    let retention = Duration::from_secs(3600);

    let mut map = BTreeMap::new();
    map.insert(active.clone(), aged(1, 0));
    map.insert(recent.clone(), aged(2, 60));
    map.insert(expired.clone(), aged(3, 7200));

    prune_materials(
        Some(&storage_dir()),
        &active,
        &mut map,
        retention,
        test_now(),
    );

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

    let retention = Duration::from_secs(60);
    prune_materials(
        Some(&storage_dir()),
        &active,
        &mut map,
        retention,
        test_now(),
    );

    assert!(map.contains_key(&active), "active key always retained");
}

#[test]
fn within_retention_at_handles_the_exact_expiry_boundary() {
    let now = test_now();
    let retention = Duration::from_secs(60);

    assert!(within_retention_at(
        now - TimeDuration::seconds(60),
        retention,
        now
    ));
    assert!(!within_retention_at(
        now - TimeDuration::seconds(61),
        retention,
        now
    ));
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
