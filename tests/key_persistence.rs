use chenxing_auth::keys::{KeyManager, KeySyncOutcome};
use chenxing_auth::oauth::token::{decode_access_token, issue_access_token};
use std::fs;
use std::time::Duration;
use uuid::Uuid;

#[test]
fn key_manager_reloads_the_same_active_key() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let first = KeyManager::load_or_generate(&directory).expect("initial key");
    let second = KeyManager::load_or_generate(&directory).expect("reloaded key");

    assert_eq!(first.key_id(), second.key_id());
    assert_eq!(first.jwks(), second.jwks());

    let _ = fs::remove_dir_all(directory);
}

#[test]
fn startup_removes_crash_left_atomic_write_temporary_files_only() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let key_id = manager.key_id();
    let key_path = directory.join(format!("rs256-{key_id}.pkcs1.der"));
    let stale_temporary_path = directory.join(".chenxing-key-crashed.tmp");
    let unrelated_temporary_path = directory.join("unrelated.tmp");

    fs::write(&stale_temporary_path, b"crash-left private key material").expect("stale file");
    fs::write(&unrelated_temporary_path, b"unrelated file").expect("unrelated file");

    let reloaded = KeyManager::load_or_generate(&directory).expect("reload key manager");

    assert_eq!(reloaded.key_id(), key_id);
    assert!(
        key_path.exists(),
        "valid persisted key must survive cleanup"
    );
    assert!(
        !stale_temporary_path.exists(),
        "atomic-write temporary file must be removed on startup"
    );
    assert!(
        unrelated_temporary_path.exists(),
        "files outside the atomic-write namespace must survive cleanup"
    );

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn reloaded_key_manager_keeps_rotated_key_for_old_token_validation() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let first = KeyManager::load_or_generate(&directory).expect("initial key");
    let old_token = issue_access_token(
        &first,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned()],
        3600,
    )
    .expect("old access token");
    first.rotate().await.expect("rotated signing key");

    let second = KeyManager::load_or_generate(&directory).expect("reloaded key manager");
    assert!(
        decode_access_token(
            &second,
            "https://auth.example.com",
            "cx_project",
            &old_token
        )
        .is_ok()
    );

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn revoking_a_persisted_key_removes_its_file_and_published_key() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let revoked_key_id = manager.key_id();
    let revoked_key_path = directory.join(format!("rs256-{revoked_key_id}.pkcs1.der"));
    manager.rotate().await.expect("rotated signing key");

    manager
        .revoke(&revoked_key_id)
        .await
        .expect("revoked persisted key");

    assert!(!revoked_key_path.exists());
    assert!(manager.verification_key_for(&revoked_key_id).is_none());
    assert_eq!(manager.jwks().keys.len(), 1);
    let reloaded = KeyManager::load_or_generate(&directory).expect("reloaded key manager");
    assert!(reloaded.verification_key_for(&revoked_key_id).is_none());
    assert_eq!(reloaded.jwks().keys.len(), 1);

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn revoking_a_persisted_active_key_switches_before_removing_it() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let previous_key_id = manager.key_id();
    manager.rotate().await.expect("rotated signing key");
    let active_key_id = manager.key_id();
    let active_key_path = directory.join(format!("rs256-{active_key_id}.pkcs1.der"));

    let revocation = manager
        .revoke(&active_key_id)
        .await
        .expect("revoked active persisted key");

    assert_eq!(revocation.active_key_id, previous_key_id);
    assert_eq!(manager.key_id(), previous_key_id);
    assert!(!active_key_path.exists());
    assert_eq!(
        fs::read_to_string(directory.join("active-rs256.kid")).expect("active key id"),
        previous_key_id
    );

    let reloaded = KeyManager::load_or_generate(&directory).expect("reloaded key manager");
    assert_eq!(reloaded.key_id(), previous_key_id);
    assert!(reloaded.verification_key_for(&active_key_id).is_none());

    let _ = fs::remove_dir_all(directory);
}

/// Issue #298：长期在役的 key 退役后必须拿到完整的保留窗口。
///
/// 夹具把 key 文件的 mtime 推到远早于 retention 的过去，模拟“在役数周才轮换”。
/// 按创建时刻裁剪的旧实现会在轮换的同一瞬间删掉它，把它最后一刻签发、尚未到
/// `exp` 的令牌一起作废；正确实现从退役时刻起算，公钥必须继续发布。
#[tokio::test]
async fn a_long_lived_key_stays_verifiable_after_it_is_rotated_out() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let retention = Duration::from_secs(60);
    let manager =
        KeyManager::load_or_generate_with_retention(&directory, retention).expect("initial key");
    let long_lived_key_id = manager.key_id();
    let long_lived_path = directory.join(format!("rs256-{long_lived_key_id}.pkcs1.der"));
    age_file(&long_lived_path, Duration::from_secs(30 * 24 * 60 * 60));

    // 重新加载让远古 mtime 生效，并确认它仍然是 active：在役 key 不受窗口约束。
    let manager = KeyManager::load_or_generate_with_retention(&directory, retention)
        .expect("reload with an aged key file");
    assert_eq!(manager.key_id(), long_lived_key_id);

    let old_token = issue_access_token(
        &manager,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned()],
        3600,
    )
    .expect("token signed just before retirement");
    manager
        .rotate()
        .await
        .expect("rotate the long-lived key out");

    assert!(
        long_lived_path.exists(),
        "a key retired this instant must keep its full retention window"
    );
    assert!(manager.verification_key_for(&long_lived_key_id).is_some());
    assert_eq!(manager.jwks().keys.len(), 2);
    decode_access_token(
        &manager,
        "https://auth.example.com",
        "cx_project",
        &old_token,
    )
    .expect("a token signed before retirement must stay verifiable");

    let reloaded = KeyManager::load_or_generate_with_retention(&directory, retention)
        .expect("reload after rotation");
    assert!(
        reloaded.verification_key_for(&long_lived_key_id).is_some(),
        "the retirement instant must survive a reload"
    );

    let _ = fs::remove_dir_all(directory);
}

/// 退役记录必须随材料一起回收，否则目录里会积累无主记录。
#[tokio::test]
async fn retirement_records_are_collected_with_their_key_material() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let retired_key_id = manager.key_id();
    manager.rotate().await.expect("rotated signing key");
    let record_path = directory.join(format!("rs256-{retired_key_id}.retired"));
    assert!(
        record_path.exists(),
        "rotation must record the retirement instant"
    );

    manager
        .revoke(&retired_key_id)
        .await
        .expect("revoke the retired key");

    assert!(
        !record_path.exists(),
        "revocation must collect the retirement record with the material"
    );

    let _ = fs::remove_dir_all(directory);
}

/// 吊销 active key 会把一个已退役的 key 重新推上役，它的记录必须消失。
#[tokio::test]
async fn a_key_that_becomes_active_again_loses_its_retirement_record() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let previous_key_id = manager.key_id();
    manager.rotate().await.expect("rotated signing key");
    let active_key_id = manager.key_id();
    let previous_record = directory.join(format!("rs256-{previous_key_id}.retired"));
    assert!(previous_record.exists(), "fixture must start retired");

    manager
        .revoke(&active_key_id)
        .await
        .expect("revoke the active key");

    assert_eq!(manager.key_id(), previous_key_id);
    let reloaded = KeyManager::load_or_generate(&directory).expect("reload after revocation");
    assert_eq!(reloaded.key_id(), previous_key_id);
    assert!(
        !previous_record.exists(),
        "a key that is active again must not keep a retirement record"
    );

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn zero_retention_reclaims_old_private_key_after_rotation() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate_with_retention(&directory, Duration::ZERO)
        .expect("initial key");
    let old_key_id = manager.key_id();
    let old_key_path = directory.join(format!("rs256-{old_key_id}.pkcs1.der"));

    manager.rotate().await.expect("rotated signing key");

    assert!(!old_key_path.exists());
    assert_eq!(manager.jwks().keys.len(), 1);
    let reloaded =
        KeyManager::load_or_generate_with_retention(&directory, Duration::ZERO).expect("reload");
    assert_eq!(reloaded.jwks().keys.len(), 1);
    assert!(reloaded.decoding_key_for(&old_key_id).is_err());

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn failed_active_key_persist_keeps_in_memory_key_unchanged() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let old_key_id = manager.key_id();
    let active_path = directory.join("active-rs256.kid");
    fs::remove_file(&active_path).expect("remove active id");
    fs::create_dir(&active_path).expect("block active id replacement");

    assert!(manager.rotate().await.is_err());
    assert_eq!(manager.key_id(), old_key_id);
    assert_eq!(manager.jwks().keys.len(), 1);
    assert_eq!(persisted_key_count(&directory), 1);

    fs::remove_dir(&active_path).expect("remove blocker");
    fs::write(&active_path, &old_key_id).expect("restore active id");
    let reloaded = KeyManager::load_or_generate(&directory).expect("reload after failure");
    assert_eq!(reloaded.key_id(), old_key_id);

    let _ = fs::remove_dir_all(directory);
}

#[test]
fn legacy_private_key_is_migrated_and_removed() {
    let source_directory =
        std::env::temp_dir().join(format!("chenxing-key-source-{}", Uuid::new_v4()));
    let source = KeyManager::load_or_generate(&source_directory).expect("source key");
    let key_id = source.key_id();
    let key_path = source_directory.join(format!("rs256-{key_id}.pkcs1.der"));
    let der = fs::read(key_path).expect("source private key");

    let directory = std::env::temp_dir().join(format!("chenxing-legacy-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("legacy directory");
    fs::write(directory.join("active-rs256.pkcs1.der"), der).expect("legacy private key");
    fs::write(directory.join("active-rs256.kid"), &key_id).expect("legacy active id");

    let manager = KeyManager::load_or_generate(&directory).expect("migrate legacy key");
    assert_eq!(manager.key_id(), key_id);
    assert!(!directory.join("active-rs256.pkcs1.der").exists());
    assert!(directory.join(format!("rs256-{key_id}.pkcs1.der")).exists());

    let _ = fs::remove_dir_all(source_directory);
    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[test]
fn signing_key_storage_permissions_are_restricted_and_repaired() {
    use std::os::unix::fs::PermissionsExt;

    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("directory mode");
    let key_path = directory.join("rs256-cx-existing.pkcs1.der");
    let active_path = directory.join("active-rs256.kid");
    fs::write(&key_path, b"invalid-key-material").expect("key file");
    fs::write(&active_path, "cx-existing").expect("active key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("key mode");
    fs::set_permissions(&active_path, fs::Permissions::from_mode(0o644)).expect("active mode");

    let result = KeyManager::load_or_generate(&directory);
    assert!(result.is_err());
    assert_eq!(
        fs::metadata(&directory)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&key_path)
            .expect("key metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&active_path)
            .expect("active metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let _ = fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[test]
fn provider_secret_storage_permissions_are_restricted_and_repaired() {
    use chenxing_auth::oauth::providers::secrets::SecretManager;
    use std::os::unix::fs::PermissionsExt;

    let directory = std::env::temp_dir().join(format!("chenxing-secrets-{}", Uuid::new_v4()));
    let manager = SecretManager::load_or_generate(&directory).expect("provider secret");
    let path = manager.path().expect("provider secret path");
    assert_eq!(
        fs::metadata(&directory)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(path)
            .expect("secret metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("secret mode");
    let reloaded = SecretManager::load_or_generate(&directory).expect("reloaded provider secret");
    assert_eq!(
        fs::metadata(reloaded.path().expect("reloaded path"))
            .expect("reloaded metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn concurrent_rotations_are_serialized_without_losing_keys() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let manager = manager.clone();
        tasks.push(tokio::spawn(async move { manager.rotate().await }));
    }

    let mut key_ids = Vec::new();
    for task in tasks {
        key_ids.push(task.await.expect("rotation task").expect("rotation"));
    }
    key_ids.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    key_ids.dedup_by(|left, right| left.key_id == right.key_id);
    assert_eq!(key_ids.len(), 4);
    assert_eq!(manager.jwks().keys.len(), 5);

    let _ = fs::remove_dir_all(directory);
}

/// 多实例一致性由显式的磁盘同步提供，而不是每次签发都 reload（Issue #257）。
#[tokio::test]
async fn managers_adopt_shared_active_key_after_disk_sync() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let first = KeyManager::load_or_generate(&directory).expect("initial key");
    let second = KeyManager::load_or_generate(&directory).expect("second manager");
    let stale_key_id = second.key_id();

    let rotation = first.rotate().await.expect("rotate signing key");
    // 同步之前第二个实例仍用自己的快照签名：热路径不做磁盘 IO。
    assert_eq!(second.active_signing_key().key_id(), stale_key_id);

    assert_eq!(
        second.sync_from_disk().await.expect("sync shared keys"),
        KeySyncOutcome::Updated
    );
    assert_eq!(second.active_signing_key().key_id(), rotation.key_id);

    let token = issue_access_token(
        &second,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned()],
        3600,
    )
    .expect("sign with synchronized key");
    let header = jsonwebtoken::decode_header(&token).expect("token header");
    assert_eq!(header.kid.as_deref(), Some(rotation.key_id.as_str()));
    decode_access_token(&second, "https://auth.example.com", "cx_project", &token)
        .expect("verify with synchronized key");

    // 磁盘未再变化时同步是幂等的，不应替换内存快照。
    assert_eq!(
        second.sync_from_disk().await.expect("idempotent sync"),
        KeySyncOutcome::Unchanged
    );

    let _ = fs::remove_dir_all(directory);
}

/// 目录锁被别的 fd 占用时，热路径必须继续用内存快照服务，而不是返回错误。
///
/// flock 的锁归属是 open file description，同一进程内不同 fd 之间同样互斥，
/// 因此这里持有的锁精确复现了 Issue #257 里两个并发请求互相抢锁的场景。
#[tokio::test]
async fn hot_paths_serve_memory_snapshot_while_storage_lock_is_held() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let active_key_id = manager.key_id();
    let published_key_count = manager.jwks().keys.len();

    let _lock_holder = lock_key_storage(&directory);

    // 签发、验证、JWKS 三条热路径都不碰磁盘，因此锁被占用时全部正常返回。
    let token = issue_access_token(
        &manager,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned()],
        3600,
    )
    .expect("issue while storage lock is held");
    decode_access_token(&manager, "https://auth.example.com", "cx_project", &token)
        .expect("verify while storage lock is held");
    assert_eq!(manager.active_signing_key().key_id(), active_key_id);
    assert!(manager.verification_key_for(&active_key_id).is_some());
    assert_eq!(manager.jwks().keys.len(), published_key_count);

    // 后台同步把锁竞争降级为“跳过本轮”，不产生错误。
    assert_eq!(
        manager.sync_from_disk().await.expect("contended sync"),
        KeySyncOutcome::Contended
    );

    let _ = fs::remove_dir_all(directory);
}

/// 并发热路径不再互相抢锁：同时签发与验证必须全部成功。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_hot_path_requests_all_succeed() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let manager = manager.clone();
        tasks.push(tokio::spawn(async move {
            let token = issue_access_token(
                &manager,
                "https://auth.example.com",
                "user-1",
                "cx_project",
                &["openid".to_owned()],
                3600,
            )
            .expect("concurrent issue");
            decode_access_token(&manager, "https://auth.example.com", "cx_project", &token)
                .expect("concurrent verify");
            assert!(!manager.jwks().keys.is_empty());
        }));
    }
    for task in tasks {
        task.await.expect("hot path task");
    }

    let _ = fs::remove_dir_all(directory);
}

/// 后台同步任务把别的实例轮换出的密钥带进本实例的内存快照。
///
/// 未知 `kid` 的验证失败会提示后台任务提前同步，因此不必等满一个完整周期。
#[tokio::test]
async fn disk_sync_worker_converges_on_keys_rotated_by_another_instance() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let first = KeyManager::load_or_generate(&directory).expect("initial key");
    let second = KeyManager::load_or_generate(&directory).expect("second manager");
    let worker = tokio::spawn(
        second
            .clone()
            .run_disk_sync_worker(Duration::from_millis(50)),
    );

    let rotation = first.rotate().await.expect("rotate signing key");
    let token = issue_access_token(
        &first,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned()],
        3600,
    )
    .expect("token signed by the rotating instance");

    // 提示通道：未知 kid 让 worker 提前跑一轮，而不是坐等下一个 tick。
    let _ = second.verification_key_for(&rotation.key_id);
    let converged = wait_until(Duration::from_secs(10), || {
        second.key_id() == rotation.key_id
    })
    .await;
    worker.abort();

    assert!(converged, "worker must adopt the shared active key");
    decode_access_token(&second, "https://auth.example.com", "cx_project", &token)
        .expect("verify a token signed by the other instance");

    let _ = fs::remove_dir_all(directory);
}

/// 轮换正在持有目录锁时，同步只会跳过本轮，绝不覆盖轮换刚写入的内存快照。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disk_sync_never_reverts_a_concurrent_rotation() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let manager = KeyManager::load_or_generate(&directory).expect("initial key");
    let previous_key_id = manager.key_id();

    let syncing = {
        let manager = manager.clone();
        tokio::spawn(async move {
            for _ in 0..32 {
                manager
                    .sync_from_disk()
                    .await
                    .expect("sync during rotation");
            }
        })
    };
    let rotation = manager.rotate().await.expect("rotate during sync");
    syncing.await.expect("sync task");

    // 同步收尾后内存里必须仍是轮换后的 active key。
    manager.sync_from_disk().await.expect("final sync");
    assert_ne!(rotation.key_id, previous_key_id);
    assert_eq!(manager.key_id(), rotation.key_id);
    assert!(manager.verification_key_for(&previous_key_id).is_some());

    let _ = fs::remove_dir_all(directory);
}

#[tokio::test]
async fn concurrent_manager_rotations_converge_on_shared_active_key() {
    let directory = std::env::temp_dir().join(format!("chenxing-keys-{}", Uuid::new_v4()));
    let first = KeyManager::load_or_generate(&directory).expect("initial key");
    let second = KeyManager::load_or_generate(&directory).expect("second manager");

    let (first_rotation, second_rotation) = tokio::join!(first.rotate(), second.rotate());
    let first_rotation = first_rotation.expect("first rotation");
    let second_rotation = second_rotation.expect("second rotation");
    assert_ne!(first_rotation.key_id, second_rotation.key_id);

    let reloaded = KeyManager::load_or_generate(&directory).expect("reloaded key manager");
    let active_key_id = reloaded.key_id();
    assert!(
        active_key_id == first_rotation.key_id || active_key_id == second_rotation.key_id,
        "disk active key must be one of the serialized rotations"
    );
    assert_eq!(reloaded.jwks().keys.len(), 3);
    first.sync_from_disk().await.expect("first manager sync");
    second.sync_from_disk().await.expect("second manager sync");
    assert_eq!(first.active_signing_key().key_id(), active_key_id.as_str());
    assert_eq!(second.active_signing_key().key_id(), active_key_id.as_str());

    let _ = fs::remove_dir_all(directory);
}

/// 在测试进程里独占密钥目录锁，模拟“另一个实例或本进程的轮换正在写目录”。
///
/// 直接用 flock 而不是调用生产代码的锁类型：`KeyStorageLock` 是 crate 内部类型，
/// 而这里要验证的正是“外部持锁时热路径依然可用”这一外部可观察行为。
#[cfg(unix)]
fn lock_key_storage(directory: &std::path::Path) -> fs::File {
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn flock(fd: std::ffi::c_int, operation: std::ffi::c_int) -> std::ffi::c_int;
    }
    const LOCK_EX: std::ffi::c_int = 2;
    const LOCK_NB: std::ffi::c_int = 4;

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(".chenxing-key.lock"))
        .expect("open key storage lock file");
    assert_eq!(
        unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) },
        0,
        "test must own the key storage lock"
    );
    file
}

/// 非 Unix 回退实现用目录存在表达持锁，见 `src/key_lock.rs`。
#[cfg(not(unix))]
fn lock_key_storage(directory: &std::path::Path) -> LockDirectoryGuard {
    let path = directory.join(".chenxing-key.lock");
    fs::create_dir(&path).expect("own the key storage lock");
    LockDirectoryGuard { path }
}

#[cfg(not(unix))]
struct LockDirectoryGuard {
    path: std::path::PathBuf,
}

#[cfg(not(unix))]
impl Drop for LockDirectoryGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

/// 轮询等待条件成立，用于后台任务这种没有完成信号的收敛断言。
async fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    condition()
}

/// 把文件 mtime 推到过去，模拟“这个 key 已经在役很久了”。
///
/// mtime 是创建时刻的唯一来源，因此这是让加载看到一个远古 key 的唯一办法。
fn age_file(path: &std::path::Path, age: Duration) {
    let file = fs::File::options()
        .write(true)
        .open(path)
        .expect("open key file");
    file.set_modified(std::time::SystemTime::now() - age)
        .expect("set key file mtime");
}

fn persisted_key_count(directory: &std::path::Path) -> usize {
    fs::read_dir(directory)
        .expect("key directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("rs256-") && name.ends_with(".pkcs1.der"))
        })
        .count()
}
