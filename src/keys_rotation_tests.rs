//! 轮换、保留窗口与 JWKS 发布的单元测试。
//!
//! 覆盖：内存模式发布集合有界（Issue #285）、退役保留窗口边界（Issue #298/#316/#317）、
//! Zeroizing 包装后签名链路功能不破坏、JWKS 不泄漏 RSA 私钥参数（RFC 7518 §6.3.2），
//! 以及无共享目录时的同步与 worker 行为。

use std::time::Duration;

use time::{Duration as TimeDuration, OffsetDateTime};

use crate::oauth::token::{decode_access_token, issue_access_token};

use super::prune::retirement_window_open_at;
use super::{
    DEFAULT_KEY_RETENTION_SECONDS, KeyManager, KeySyncOutcome, MINIMUM_KEY_SYNC_INTERVAL, prune,
};

const TEST_NOW_UNIX_SECONDS: i64 = 1_700_000_000;

fn test_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(TEST_NOW_UNIX_SECONDS).expect("valid test timestamp")
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

    assert!(prune::retirement_window_open_at(
        Some(now - TimeDuration::seconds(59)),
        retention,
        Duration::ZERO,
        now
    ));
    assert!(
        !prune::retirement_window_open_at(
            Some(now - TimeDuration::seconds(60)),
            retention,
            Duration::ZERO,
            now
        ),
        "窗口右端点排他"
    );
}

/// 尚未退役的 key 不受保留窗口约束：它仍在签发，删掉就直接断签名链路。
#[test]
fn retirement_window_open_at_never_closes_for_an_active_key() {
    assert!(prune::retirement_window_open_at(
        None,
        Duration::ZERO,
        Duration::ZERO,
        test_now()
    ));
}

/// Issue #316 的核心回归：跨实例时钟偏差不得提前关闭保留窗口。
///
/// `retired_at` 由退役实例的时钟写入，本实例的时钟可能偏快。按 `retention` 判断，
/// 快钟实例会在真实窗口结束前就判定过期并删除共享密钥文件；加上
/// `skew_allowance` 后，偏差不超过容忍值的实例只会晚删、绝不提前删。
#[test]
fn retirement_window_open_at_tolerates_a_fast_local_clock() {
    let now = test_now();
    let retention = Duration::from_secs(600);
    let skew_allowance = Duration::from_secs(300);

    // 退役实例比本实例慢 300 秒：本实例看到 elapsed = retention，但真实只过了
    // retention - 300，窗口必须仍然开着。
    assert!(prune::retirement_window_open_at(
        Some(now - TimeDuration::seconds(600)),
        retention,
        skew_allowance,
        now
    ));
    // 偏差恰好等于容忍值：窗口在 `retention + allowance` 处关闭（右端点排他）。
    assert!(
        !prune::retirement_window_open_at(
            Some(now - TimeDuration::seconds(900)),
            retention,
            skew_allowance,
            now
        ),
        "窗口右端点排他，偏差超过容忍值才能关闭"
    );
    // 慢钟方向（本实例时钟偏慢，`retired_at` 在未来）由同一个比较天然覆盖。
    assert!(prune::retirement_window_open_at(
        Some(now + TimeDuration::hours(1)),
        retention,
        skew_allowance,
        now
    ));
}

/// 超过 `time::Duration` 可表示范围（i64 纳秒上界约 292 年）的 retention 必须按
/// 「窗口永不关闭」处理，不能退回「窗口已关闭」——否则退役公钥被立即从 JWKS
/// 与磁盘删除，其签发的未过期令牌全部失效（Issue #317）。失败方向必须 fail-safe。
#[test]
fn retirement_window_open_at_fails_safe_when_retention_is_unrepresentable() {
    let retention = Duration::from_secs(u64::MAX); // 约 5840 亿年，远超 i64 纳秒上界
    assert!(retirement_window_open_at(
        Some(test_now() - TimeDuration::days(1)),
        retention,
        Duration::ZERO,
        test_now(),
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
