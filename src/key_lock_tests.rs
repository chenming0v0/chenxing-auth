//! 内核句柄锁与 portable fallback 的生命周期回归测试（Issues #286/#355/#545）。

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use super::{KEY_STORAGE_LOCK_FILE, KeyStorageLock, directory_lock};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let unique = uuid::Uuid::new_v4().simple();
        let path = std::env::temp_dir().join(format!("chenxing-lock-{name}-{unique}"));
        fs::create_dir_all(&path).expect("temp directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn lock_path(&self) -> PathBuf {
        self.0.join(KEY_STORAGE_LOCK_FILE)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn lock_round_trips_acquire_release_and_reacquire() {
    let directory = TempDir::new("round-trip");

    let first = KeyStorageLock::acquire(directory.path()).expect("first owner");
    let error = KeyStorageLock::try_acquire(directory.path()).expect_err("lock is exclusive");
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

    drop(first);
    KeyStorageLock::try_acquire(directory.path()).expect("successor owner");
}

#[test]
fn lock_uses_handle_ownership_instead_of_pid_or_file_contents() {
    let directory = TempDir::new("ignore-pid");
    fs::write(directory.lock_path(), std::process::id().to_string())
        .expect("plant legacy pid metadata");

    let _lock = KeyStorageLock::try_acquire(directory.path())
        .expect("an unlocked file is acquirable even when its contents reuse this pid");
}

#[test]
fn lock_file_survives_release_so_an_old_owner_cannot_delete_a_successor() {
    let directory = TempDir::new("no-delete");

    let first = KeyStorageLock::acquire(directory.path()).expect("first owner");
    assert!(directory.lock_path().is_file());
    drop(first);
    assert!(
        directory.lock_path().is_file(),
        "release closes the kernel handle; it must not unlink shared lock state"
    );

    let successor = KeyStorageLock::try_acquire(directory.path()).expect("successor owner");
    drop(successor);
    assert!(directory.lock_path().is_file());
}

#[test]
fn lock_remains_exclusive_while_the_holder_is_paused() {
    let directory = TempDir::new("paused");
    let holder = KeyStorageLock::acquire(directory.path()).expect("holder");

    std::thread::sleep(Duration::from_millis(100));
    let error = KeyStorageLock::try_acquire(directory.path()).expect_err("paused owner stays live");
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

    drop(holder);
    KeyStorageLock::try_acquire(directory.path()).expect("lock recovers after handle closes");
}

#[test]
fn lock_recovers_when_a_process_exits_without_running_drop() {
    let directory = TempDir::new("crash");
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("lock_holder_exits_without_drop_helper")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env("CHENXING_CRASH_LOCK_DIR", directory.path())
        .status()
        .expect("spawn lock holder");
    assert_eq!(
        status.code(),
        Some(73),
        "helper must exit without unwinding"
    );

    KeyStorageLock::try_acquire(directory.path())
        .expect("the kernel must release an abandoned handle at process exit");
}

#[test]
fn lock_holder_exits_without_drop_helper() {
    let Some(directory) = std::env::var_os("CHENXING_CRASH_LOCK_DIR") else {
        return;
    };
    let _lock = KeyStorageLock::acquire(Path::new(&directory)).expect("child acquires lock");
    std::process::exit(73);
}

#[cfg(windows)]
#[test]
fn lock_rejects_a_legacy_directory_lease_instead_of_reclaiming_it() {
    let directory = TempDir::new("legacy-directory");
    fs::create_dir(directory.lock_path()).expect("plant legacy directory lease");

    let error = KeyStorageLock::try_acquire(directory.path()).expect_err("must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(directory.lock_path().is_dir());
}

fn fallback_identity(
    host: &str,
    pid: u32,
    process_start: u128,
    nonce: &str,
) -> directory_lock::LeaseIdentity {
    directory_lock::identity_for_test(host, pid, process_start, nonce)
}

fn plant_fallback_lock(
    directory: &TempDir,
    identity: &directory_lock::LeaseIdentity,
    age: Duration,
) {
    let lock_path = directory.lock_path();
    fs::create_dir(&lock_path).expect("plant fallback lock directory");
    directory_lock::write_owner_for_test(&lock_path, identity, false);
    let owner_path = directory_lock::owner_file_for_test(&lock_path);
    fs::File::options()
        .write(true)
        .open(owner_path)
        .expect("open owner record")
        .set_modified(SystemTime::now() - age)
        .expect("age owner record");
}

fn fallback_stale_age() -> Duration {
    directory_lock::stale_lock_age() + Duration::from_secs(1)
}

#[test]
fn fallback_heartbeat_refreshes_only_the_matching_fencing_token() {
    let directory = TempDir::new("fallback-heartbeat");
    let lock_path = directory.lock_path();
    fs::create_dir(&lock_path).expect("create fallback lock directory");
    let owner = fallback_identity("host-a", 41, 100, "owner-nonce");
    directory_lock::write_owner_for_test(&lock_path, &owner, false);
    let owner_path = directory_lock::owner_file_for_test(&lock_path);
    fs::File::options()
        .write(true)
        .open(&owner_path)
        .expect("open owner record")
        .set_modified(SystemTime::UNIX_EPOCH)
        .expect("set old heartbeat");

    let mut heartbeat = directory_lock::Heartbeat::start(
        owner_path.clone(),
        owner,
        Duration::from_millis(10),
    );
    let refresh_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let modified = fs::metadata(&owner_path)
            .expect("owner metadata")
            .modified()
            .expect("owner mtime");
        if modified > SystemTime::UNIX_EPOCH {
            break;
        }
        assert!(
            Instant::now() < refresh_deadline,
            "matching fencing token must refresh the heartbeat"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let successor = fallback_identity("host-a", 41, 100, "successor-nonce");
    directory_lock::write_owner_for_test(&lock_path, &successor, false);
    let successor_record = fs::read_to_string(&owner_path).expect("successor owner record");
    let stop_deadline = Instant::now() + Duration::from_secs(2);
    while !heartbeat.is_finished() {
        assert!(
            Instant::now() < stop_deadline,
            "heartbeat must stop after the owner token changes"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    heartbeat.stop();
    assert_eq!(
        fs::read_to_string(owner_path).expect("owner record after heartbeat stops"),
        successor_record,
        "an old heartbeat must never overwrite its successor's token"
    );
}

#[test]
fn fallback_pid_collision_uses_host_and_process_start_for_fencing() {
    let now = SystemTime::now();
    let expired = now - fallback_stale_age();
    let current = fallback_identity("host-a", 77, 200, "current");

    for foreign in [
        fallback_identity("host-a", 77, 199, "old-process"),
        fallback_identity("host-b", 77, 200, "other-host"),
    ] {
        assert!(directory_lock::is_stale(
            directory_lock::observed_for_test(Some((foreign, false)), Some(expired)),
            &current,
            now,
        ));
    }
}

#[test]
fn fallback_never_reclaims_the_same_process_after_a_pause() {
    let now = SystemTime::now();
    let current = fallback_identity("host-a", 88, 300, "current-lease");
    let older_lease = fallback_identity("host-a", 88, 300, "older-lease");

    assert!(
        !directory_lock::is_stale(
            directory_lock::observed_for_test(
                Some((older_lease, false)),
                Some(now - fallback_stale_age()),
            ),
            &current,
            now,
        ),
        "a paused lease from this process must not be reclaimed despite an old mtime"
    );
}

#[test]
fn fallback_reclaims_a_crashed_process_record() {
    let directory = TempDir::new("fallback-crash");
    let crashed = fallback_identity("foreign-host", u32::MAX - 1, 1, "crashed");
    plant_fallback_lock(&directory, &crashed, fallback_stale_age());

    assert!(
        directory_lock::reclaim_if_stale(&directory.lock_path(), SystemTime::now())
            .expect("reclaim stale fallback lease")
    );
    assert!(!directory.lock_path().exists());
}

#[test]
fn fallback_release_cannot_remove_or_rewrite_a_successor() {
    let directory = TempDir::new("fallback-successor");
    let mut predecessor =
        directory_lock::acquire(directory.path(), false).expect("predecessor lease");
    let successor = fallback_identity("host-b", 900, 700, "successor");
    directory_lock::write_owner_for_test(&directory.lock_path(), &successor, false);
    let owner_path = directory_lock::owner_file_for_test(&directory.lock_path());
    let successor_record = fs::read_to_string(&owner_path).expect("successor record");

    predecessor.release();

    assert!(directory.lock_path().is_dir());
    assert_eq!(
        fs::read_to_string(owner_path).expect("successor record after old release"),
        successor_record,
        "release must validate the full fencing token before changing shared state"
    );
}

#[test]
fn fallback_release_marker_allows_a_successor_to_acquire() {
    let directory = TempDir::new("fallback-release");
    let mut predecessor =
        directory_lock::acquire(directory.path(), false).expect("predecessor lease");
    predecessor.release();
    assert!(directory.lock_path().is_dir(), "release leaves a fenced marker");

    let mut successor =
        directory_lock::acquire(directory.path(), false).expect("successor reclaims marker");
    assert_eq!(successor.path(), directory.lock_path());
    successor.release();
}
