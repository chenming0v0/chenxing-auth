//! 后台同步必须完成到期激活，不能只把磁盘快照抄进内存（Issue #655）。

use std::time::Duration;

use time::{Duration as TimeDuration, OffsetDateTime};

use super::super::DEFAULT_KEY_RETENTION_SECONDS;
use super::{KeyManager, KeySyncOutcome};

fn persisted_manager(directory: &std::path::Path, delay: Duration) -> KeyManager {
    KeyManager::load_or_generate_with_lifecycle(
        directory,
        Duration::from_secs(DEFAULT_KEY_RETENTION_SECONDS),
        Duration::ZERO,
        delay,
    )
    .expect("persisted manager")
}

/// 窗口未到时，同步必须继续用旧 key 签发，并把 pending 留在盘上。
#[tokio::test]
async fn disk_sync_does_not_promote_a_future_published_key() {
    let directory = std::env::temp_dir().join(format!(
        "chenxing-sync-future-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let delay = Duration::from_secs(65);
    let manager = persisted_manager(&directory, delay);
    let old_key_id = manager.key_id();
    let now = OffsetDateTime::now_utc();
    let rotation = manager.rotate_at(now).await.expect("publish rotation");

    let outcome = manager
        .sync_from_disk_blocking_at(now)
        .expect("sync before deadline");

    assert_ne!(outcome, KeySyncOutcome::NotPersisted);
    assert_eq!(manager.key_id(), old_key_id);
    assert_eq!(
        manager.published_key_id().as_deref(),
        Some(rotation.key_id.as_str())
    );

    let _ = std::fs::remove_dir_all(directory);
}

/// 窗口已到时，同步必须把签发权切过去——这是生产路径，不是测试里的手动激活。
#[tokio::test]
async fn disk_sync_promotes_a_due_published_key() {
    let directory = std::env::temp_dir().join(format!(
        "chenxing-sync-due-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let delay = Duration::from_secs(65);
    let manager = persisted_manager(&directory, delay);
    let old_key_id = manager.key_id();
    let now = OffsetDateTime::now_utc();
    let rotation = manager.rotate_at(now).await.expect("publish rotation");
    assert_eq!(manager.key_id(), old_key_id);

    let outcome = manager
        .sync_from_disk_blocking_at(now + TimeDuration::seconds(65))
        .expect("sync after deadline");

    assert_eq!(outcome, KeySyncOutcome::Updated);
    assert_eq!(manager.key_id(), rotation.key_id);
    assert!(manager.published_key_id().is_none());
    assert!(
        manager.verification_key_for(&old_key_id).is_some(),
        "old public key stays in the verification window"
    );

    let _ = std::fs::remove_dir_all(directory);
}
