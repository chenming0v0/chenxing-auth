//! 单元测试：非 Unix 目录锁的陈旧锁识别与回收（Issue #286）。
//!
//! 生产路径在 Unix 上走 flock，这段回退实现只在非 Unix 平台生效；但 CI 跑在
//! Linux 上，所以 `directory_lock` 在测试配置下对所有平台编译，逻辑由这里覆盖。
//! 核心约束是两条相反的失败模式都不能出现：崩溃遗留的锁必须能被回收（否则密钥
//! 目录永久阻塞），活锁绝不能被误删（否则两个进程同时写私钥材料）。活锁的判据
//! 是心跳：持锁者周期性刷新 owner 文件 mtime，持锁多久都不会被误判（Issue #355）。

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use super::directory_lock;

/// 独占临时目录，drop 时清理。
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
        self.0.join(".chenxing-key.lock")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 在目录里植入一把锁：指定持锁 pid 与"最后一次心跳已经过去多久"。
///
/// 年龄通过回拨 owner 文件的 mtime 表达——`observe` 优先取该文件的 mtime，
/// 而普通文件的 mtime 在所有平台上都能稳定设置（目录 mtime 不能）。在心跳
/// 语义下，回拨 mtime 即"最后一次心跳距今"。
fn plant_lock(directory: &TempDir, owner_pid: Option<u32>, age: Duration) {
    let lock_path = directory.lock_path();
    fs::create_dir(&lock_path).expect("plant lock directory");
    let owner_path = directory_lock::owner_file(&lock_path);
    let contents = owner_pid.map(|pid| pid.to_string()).unwrap_or_default();
    fs::write(&owner_path, contents).expect("plant lock owner");
    let file = fs::File::options()
        .write(true)
        .open(&owner_path)
        .expect("open lock owner");
    file.set_modified(SystemTime::now() - age)
        .expect("age the lock owner file");
}

/// 一个几乎不可能属于活跃进程的 pid，用来代表"别的进程"。
const FOREIGN_PID: u32 = u32::MAX - 1;

fn stale_age() -> Duration {
    directory_lock::stale_lock_age() + Duration::from_secs(1)
}

#[test]
fn directory_lock_reclaims_a_lock_left_by_a_crashed_process() {
    // Issue #286：崩溃遗留的锁目录不能让后续实例永久阻塞。
    let directory = TempDir::new("reclaim-stale");
    plant_lock(&directory, Some(FOREIGN_PID), stale_age());

    let lock = directory_lock::acquire(directory.path(), false).expect("stale lock is reclaimable");

    assert_eq!(lock.path(), directory.lock_path());
    assert_eq!(
        fs::read_to_string(directory_lock::owner_file(lock.path())).expect("owner file"),
        std::process::id().to_string(),
        "回收后锁必须记为本进程持有"
    );
}

#[test]
fn directory_lock_refuses_a_live_lock_held_by_another_process() {
    // 活锁绝不能被抢：两个进程同时写密钥目录会直接损坏私钥材料。
    let directory = TempDir::new("live-foreign");
    plant_lock(&directory, Some(FOREIGN_PID), Duration::from_secs(1));

    let error = directory_lock::acquire(directory.path(), false).expect_err("live lock must hold");

    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(directory.lock_path().is_dir(), "活锁的锁目录必须原样留下");
    assert_eq!(
        fs::read_to_string(directory_lock::owner_file(&directory.lock_path())).expect("owner file"),
        FOREIGN_PID.to_string(),
        "活锁的归属信息不得被改写"
    );
}

#[test]
fn directory_lock_never_reclaims_a_lock_owned_by_this_process() {
    // 同进程重入拿不到锁是既有语义（Unix 上 flock 的归属是 open file
    // description）。看起来"很旧"也不能放行，否则同一进程会拿到两把锁。
    let directory = TempDir::new("own-pid");
    plant_lock(&directory, Some(std::process::id()), stale_age());

    let error =
        directory_lock::acquire(directory.path(), false).expect_err("own lock must not be stolen");

    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(directory.lock_path().is_dir());
}

#[test]
fn directory_lock_reclaims_a_lock_without_owner_information() {
    // 崩溃发生在"建目录"与"写 pid"之间：owner 未知，只能按年龄判断。
    let directory = TempDir::new("unknown-owner");
    plant_lock(&directory, None, stale_age());

    directory_lock::acquire(directory.path(), false).expect("aged ownerless lock is reclaimable");
}

#[test]
fn directory_lock_round_trips_acquire_and_release() {
    let directory = TempDir::new("round-trip");

    let mut lock = directory_lock::acquire(directory.path(), false).expect("first acquire");
    assert!(lock.path().is_dir());
    lock.release();
    assert!(!lock.path().exists(), "释放后锁目录必须消失");

    directory_lock::acquire(directory.path(), false).expect("reacquire after release");
}

#[test]
fn directory_lock_rejects_a_lock_path_replaced_by_a_file() {
    // 锁路径被换成普通文件说明密钥目录已被篡改，必须 fail-closed 而不是回收它。
    let directory = TempDir::new("lock-is-file");
    fs::write(directory.lock_path(), b"not a lock directory").expect("plant file");

    let error = directory_lock::acquire(directory.path(), false).expect_err("must fail closed");

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        directory.lock_path().is_file(),
        "被篡改的路径不得被删除，它是唯一的证据"
    );
}

#[test]
fn is_stale_requires_both_a_foreign_owner_and_an_expired_age() {
    let now = SystemTime::now();
    let expired = now - stale_age();
    let fresh = now - Duration::from_secs(1);

    assert!(directory_lock::is_stale(
        directory_lock::observed_for_test(Some(FOREIGN_PID), Some(expired)),
        std::process::id(),
        now
    ));
    assert!(
        !directory_lock::is_stale(
            directory_lock::observed_for_test(Some(FOREIGN_PID), Some(fresh)),
            std::process::id(),
            now
        ),
        "未到门限的锁是活锁"
    );
    assert!(
        !directory_lock::is_stale(
            directory_lock::observed_for_test(Some(std::process::id()), Some(expired)),
            std::process::id(),
            now
        ),
        "本进程持有的锁永不回收"
    );
    assert!(
        !directory_lock::is_stale(
            directory_lock::observed_for_test(None, None),
            std::process::id(),
            now
        ),
        "锁不存在时没有可回收的对象"
    );
}

#[test]
fn is_stale_at_the_exact_age_boundary_and_under_a_clock_skew() {
    let now = SystemTime::now();
    let boundary = now - directory_lock::stale_lock_age();

    assert!(
        directory_lock::is_stale(
            directory_lock::observed_for_test(Some(FOREIGN_PID), Some(boundary)),
            std::process::id(),
            now
        ),
        "恰好达到门限即视为陈旧"
    );
    assert!(
        !directory_lock::is_stale(
            directory_lock::observed_for_test(
                Some(FOREIGN_PID),
                Some(boundary + Duration::from_secs(1))
            ),
            std::process::id(),
            now
        ),
        "差一秒仍是活锁"
    );
    assert!(
        !directory_lock::is_stale(
            directory_lock::observed_for_test(
                Some(FOREIGN_PID),
                Some(now + Duration::from_secs(3600))
            ),
            std::process::id(),
            now
        ),
        "时钟回拨导致的未来起始时间必须按活锁处理"
    );
}

#[test]
fn reclaim_if_stale_leaves_a_live_lock_untouched() {
    let directory = TempDir::new("reclaim-live");
    plant_lock(&directory, Some(FOREIGN_PID), Duration::from_secs(1));

    let reclaimed = directory_lock::reclaim_if_stale(&directory.lock_path(), SystemTime::now())
        .expect("observing a live lock is not an error");

    assert!(!reclaimed);
    assert!(directory.lock_path().is_dir());
}

#[test]
fn reclaim_if_stale_reports_nothing_to_do_without_a_lock() {
    let directory = TempDir::new("reclaim-absent");

    let reclaimed = directory_lock::reclaim_if_stale(&directory.lock_path(), SystemTime::now())
        .expect("absent lock is not an error");

    assert!(!reclaimed);
}

#[test]
fn heartbeat_refreshes_owner_mtime_until_stopped() {
    // Issue #355 的机制核心：持锁者用心跳刷新 owner 文件 mtime，陈旧判据从
    // "持锁开始时刻"变为"最后一次心跳"，活锁持有多久都不会被误回收。
    // 某些 CI 文件系统只提供秒级 mtime；等待实际可观测的变化，而不是假定 200ms
    // 内的两次写入一定有不同的时间戳。
    let directory = TempDir::new("heartbeat");
    fs::write(directory.path().join("owner"), FOREIGN_PID.to_string()).expect("write owner");
    let owner_path = directory.path().join("owner");
    let initial = fs::metadata(&owner_path)
        .expect("owner file")
        .modified()
        .expect("mtime");

    let mut heartbeat = directory_lock::Heartbeat::start(
        owner_path.clone(),
        FOREIGN_PID.to_string(),
        Duration::from_millis(50),
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let refreshed = loop {
        let observed = fs::metadata(&owner_path)
            .expect("owner file")
            .modified()
            .expect("mtime");
        if observed > initial {
            break observed;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "持锁期间心跳必须持续刷新 owner 文件 mtime"
        );
        std::thread::sleep(Duration::from_millis(25));
    };

    heartbeat.stop();
    std::thread::sleep(Duration::from_millis(200));
    let after = fs::metadata(&owner_path)
        .expect("owner file")
        .modified()
        .expect("mtime");
    assert_eq!(
        after, refreshed,
        "stop 后心跳线程必须退出，不得再写 owner 文件"
    );
}

#[test]
fn reclaim_if_stale_treats_a_recently_heartbeated_lock_as_live() {
    // Issue #355：锁的"年龄"从最后一次心跳算起，而不是持锁开始时刻。一把持锁
    // 很久（mtime 已超过 STALE_LOCK_AGE）的活锁，只要心跳仍在刷新，就绝不能回收。
    let directory = TempDir::new("reclaim-heartbeat");
    plant_lock(&directory, Some(FOREIGN_PID), stale_age());
    // 模拟持锁者的心跳：重写 owner 文件，把 mtime 拉回现在。
    fs::write(
        directory_lock::owner_file(&directory.lock_path()),
        FOREIGN_PID.to_string(),
    )
    .expect("heartbeat write");

    let reclaimed = directory_lock::reclaim_if_stale(&directory.lock_path(), SystemTime::now())
        .expect("observing a live lock is not an error");

    assert!(!reclaimed);
    assert!(directory.lock_path().is_dir());
}
