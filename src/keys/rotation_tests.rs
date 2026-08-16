//! 轮换、保留窗口与 JWKS 发布的单元测试。
//!
//! 覆盖：内存模式发布集合有界（Issue #285）、退役保留窗口边界（Issue #298/#316/#317）、
//! Zeroizing 包装后签名链路功能不破坏、JWKS 不泄漏 RSA 私钥参数（RFC 7518 §6.3.2），
//! 以及无共享目录时的同步与 worker 行为。

use std::time::Duration;

use time::{Duration as TimeDuration, OffsetDateTime};

use crate::oauth::token::{decode_access_token, issue_access_token};
use crate::workers::{WorkerHealth, WorkerName, WorkerSupervisor};

use super::prune::retirement_window_open_at;
use super::{
    DEFAULT_KEY_RETENTION_SECONDS, JWKS_CACHE_MAX_AGE_SECONDS, KeyManager, KeySyncOutcome,
    MINIMUM_KEY_SYNC_INTERVAL, prune,
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

/// 无共享目录时后台任务不做磁盘 IO，但必须留在 supervisor 内直到合作关停。
#[tokio::test]
async fn disk_sync_worker_stays_supervised_without_a_key_directory() {
    let manager = KeyManager::generate().expect("key generation");
    let health = WorkerHealth::new();
    let mut supervisor = WorkerSupervisor::new(health.clone());
    supervisor.spawn(WorkerName::KeySync, move |worker| {
        manager.run_disk_sync_worker(Duration::from_nanos(1), worker)
    });

    tokio::time::timeout(MINIMUM_KEY_SYNC_INTERVAL, async {
        loop {
            let status = health.status(WorkerName::KeySync);
            if status.last_success_age.is_some() {
                assert_eq!(status.phase, crate::workers::WorkerPhase::Running);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the no-op pass still records worker success");
    supervisor
        .drain(MINIMUM_KEY_SYNC_INTERVAL)
        .await
        .expect("in-memory worker shutdown");
}

#[test]
fn jwks_cache_max_age_matches_the_activation_window_lower_bound() {
    assert_eq!(JWKS_CACHE_MAX_AGE_SECONDS, 60);
}

/// Issue #454：新公钥必须先出现在 JWKS 里，签发权仍留在旧 key。
#[tokio::test]
async fn rotation_publishes_the_new_key_before_it_starts_signing() {
    let delay = Duration::from_secs(65);
    let manager = KeyManager::generate_with_activation_delay(delay).expect("key generation");
    let old_key_id = manager.key_id();
    let stale_jwks: std::collections::BTreeSet<String> = manager
        .jwks()
        .keys
        .iter()
        .filter_map(|key| key.common.key_id.clone())
        .collect();
    let now = test_now();

    let rotation = manager.rotate_at(now).await.expect("publish rotation");

    assert_ne!(rotation.key_id, old_key_id);
    assert_eq!(
        manager.key_id(),
        old_key_id,
        "must keep signing with the old key"
    );
    assert_eq!(manager.active_signing_key().key_id(), old_key_id);
    assert_eq!(
        manager.published_key_id().as_deref(),
        Some(rotation.key_id.as_str())
    );
    assert!(
        manager.verification_key_for(&rotation.key_id).is_some(),
        "new kid must be in JWKS before it signs"
    );
    assert!(
        !stale_jwks.contains(&rotation.key_id),
        "a cache that still holds the pre-rotation JWKS must not already contain the new kid"
    );
    assert_eq!(manager.jwks().keys.len(), 2);
}

/// 窗口到期后才切换签发；旧公钥继续留在验证集合里。
#[tokio::test]
async fn published_key_starts_signing_only_after_the_activation_window() {
    let delay = Duration::from_secs(65);
    let manager = KeyManager::generate_with_activation_delay(delay).expect("key generation");
    let old_key_id = manager.key_id();
    let now = test_now();
    let rotation = manager.rotate_at(now).await.expect("publish rotation");

    assert!(
        !manager
            .activate_published_at(now + TimeDuration::seconds(64))
            .await
            .expect("not due yet")
    );
    assert_eq!(manager.key_id(), old_key_id);

    assert!(
        manager
            .activate_published_at(now + TimeDuration::seconds(65))
            .await
            .expect("window elapsed")
    );
    assert_eq!(manager.key_id(), rotation.key_id);
    assert!(manager.published_key_id().is_none());
    assert!(
        manager.verification_key_for(&old_key_id).is_some(),
        "old public key stays in the verification window"
    );
}

/// 第二实例即使以 delay=0 加载，也必须遵守盘上的 `activate_at`。
#[tokio::test]
async fn a_second_instance_sees_the_published_kid_before_it_signs() {
    let directory = std::env::temp_dir().join(format!(
        "chenxing-activation-second-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let delay = Duration::from_secs(65);
    let first = KeyManager::load_or_generate_with_lifecycle(
        &directory,
        Duration::from_secs(DEFAULT_KEY_RETENTION_SECONDS),
        Duration::ZERO,
        delay,
    )
    .expect("first instance");
    let old_key_id = first.key_id();
    let stale_jwks: std::collections::BTreeSet<String> = first
        .jwks()
        .keys
        .iter()
        .filter_map(|key| key.common.key_id.clone())
        .collect();
    // 必须用真实时钟：第二实例加载走 SystemClock，盘上的 activate_at 得在未来。
    let now = OffsetDateTime::now_utc();
    let rotation = first
        .rotate_at(now)
        .await
        .expect("publish on first instance");

    let second = KeyManager::load_or_generate_with_lifecycle(
        &directory,
        Duration::from_secs(DEFAULT_KEY_RETENTION_SECONDS),
        Duration::ZERO,
        Duration::ZERO,
    )
    .expect("second instance");

    assert_eq!(second.key_id(), old_key_id);
    assert_eq!(
        second.published_key_id().as_deref(),
        Some(rotation.key_id.as_str())
    );
    assert!(
        second.verification_key_for(&rotation.key_id).is_some(),
        "second instance must serve the new public key before anyone signs with it"
    );
    assert!(
        !stale_jwks.contains(&rotation.key_id),
        "an RP still holding the old JWKS document does not yet have the new kid"
    );

    assert!(
        first
            .activate_published_at(now + TimeDuration::seconds(65))
            .await
            .expect("promote on first instance")
    );
    let reloaded = KeyManager::load_or_generate(&directory).expect("reload after promotion");
    assert_eq!(reloaded.key_id(), rotation.key_id);
    assert!(reloaded.verification_key_for(&old_key_id).is_some());

    let _ = std::fs::remove_dir_all(directory);
}

/// 窗口内再次 rotate 是幂等的：不另造一把从未签发的密钥。
#[tokio::test]
async fn rotate_during_the_activation_window_is_idempotent() {
    let manager = KeyManager::generate_with_activation_delay(Duration::from_secs(65))
        .expect("key generation");
    let now = test_now();
    let first = manager.rotate_at(now).await.expect("first publish");
    let second = manager.rotate_at(now).await.expect("second publish");

    assert_eq!(first.key_id, second.key_id);
    assert_eq!(manager.jwks().keys.len(), 2);
    assert_eq!(
        manager.published_key_id().as_deref(),
        Some(first.key_id.as_str())
    );
}
