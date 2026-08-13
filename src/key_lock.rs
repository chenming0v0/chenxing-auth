use std::{
    fs,
    io::{self, ErrorKind},
    path::Path,
};

#[cfg(unix)]
use std::fs::{File, OpenOptions};

#[cfg(unix)]
use super::{PRIVATE_FILE_MODE, invalid_storage_path, secure_existing_file};

const KEY_STORAGE_LOCK_FILE: &str = ".chenxing-key.lock";

#[cfg(unix)]
use std::ffi::c_int;

#[cfg(unix)]
const LOCK_EX: c_int = 2;
#[cfg(unix)]
const LOCK_NB: c_int = 4;
#[cfg(unix)]
const LOCK_UN: c_int = 8;

#[cfg(unix)]
unsafe extern "C" {
    fn flock(fd: c_int, operation: c_int) -> c_int;
}

/// 共享密钥目录的进程级互斥锁。
///
/// Unix 上使用内核管理的 advisory lock，而不是靠留下一个需要手工清理的
/// lock 文件。持有锁的进程崩溃后，文件描述符关闭，后续实例仍可继续启动。
///
/// 非 Unix 平台没有等价的标准库原语，回退实现见 `directory_lock`：它用目录创建
/// 表达互斥，并额外承担 Unix 上由内核免费提供的那件事——识别崩溃遗留的锁；
/// 持锁期间用周期性心跳向其他实例证明本进程活着（Issue #355）。
pub(crate) struct KeyStorageLock {
    #[cfg(unix)]
    file: File,
    #[cfg(not(unix))]
    lock: directory_lock::DirectoryLock,
}

impl KeyStorageLock {
    pub(crate) fn acquire(directory: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let file = open_lock_file(directory)?;
            lock_file(&file, false)?;
            Ok(Self { file })
        }

        #[cfg(not(unix))]
        {
            let lock = directory_lock::acquire(directory, true)?;
            Ok(Self { lock })
        }
    }

    pub(crate) fn try_acquire(directory: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let file = open_lock_file(directory)?;
            lock_file(&file, true)?;
            Ok(Self { file })
        }

        #[cfg(not(unix))]
        {
            let lock = directory_lock::acquire(directory, false)?;
            Ok(Self { lock })
        }
    }
}

#[cfg(unix)]
impl Drop for KeyStorageLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let _ = unsafe { flock(self.file.as_raw_fd(), LOCK_UN) };
    }
}

#[cfg(not(unix))]
impl Drop for KeyStorageLock {
    fn drop(&mut self) {
        self.lock.release();
    }
}

#[cfg(unix)]
fn open_lock_file(directory: &Path) -> io::Result<File> {
    let path = directory.join(KEY_STORAGE_LOCK_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() => secure_existing_file(&path)?,
        Ok(_) => return Err(invalid_storage_path()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(PRIVATE_FILE_MODE);
    let file = options.open(&path)?;
    secure_existing_file(&path)?;
    Ok(file)
}

#[cfg(unix)]
fn lock_file(file: &File, nonblocking: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let operation = LOCK_EX | if nonblocking { LOCK_NB } else { 0 };
    let result = unsafe { flock(file.as_raw_fd(), operation) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 非 Unix 平台的锁回退实现：用目录创建作为互斥原语。
///
/// `create_dir` 在所有目标平台上都是原子的"创建或失败"，因此互斥本身没问题。
/// 问题在于释放：Unix 的 flock 由内核在进程消失时自动归还，而目录不会——持锁
/// 进程崩溃后目录留在盘上，后续实例的每次 `acquire` 都撞 `AlreadyExists`，
/// 轮换、吊销和后台同步全部永久阻塞，只能人工删目录（Issue #286）。
///
/// 因此这里给锁目录附一份归属与活性信息：`owner` 文件记录持锁进程的 pid；
/// 持锁期间一个心跳线程每 [`HEARTBEAT_INTERVAL`] 重写一次该文件，把"最后一次
/// 心跳"刻进文件 mtime。陈旧判据是"不是本进程"且"超过 [`STALE_LOCK_AGE`] 没有
/// 心跳"。这比按持锁开始时刻判龄更安全：活锁持有多久（慢文件系统、大密钥集）
/// 心跳都在刷新，永远不会被误回收；崩溃进程的心跳随进程终止，锁在死亡后最多
/// 阻塞一分钟（Issue #355）。
///
/// 判据刻意保守：
///
/// - pid 相同一律视为活锁。同进程重入拿不到锁是既有语义（Unix 上 flock 的
///   归属是 open file description，同进程不同 fd 同样互斥），不能因为"看起来
///   很旧"就放行。
/// - 心跳缺席未到门限一律视为活锁。[`STALE_LOCK_AGE`] 是心跳间隔的 12 倍，
///   正常调度的进程不可能连续缺席这么久，偶尔错过一两次心跳（调度抖动）
///   不会被误杀。
/// - 回收前重新观测一次归属信息，只在 pid 与 mtime 都没变过时才删。这把"另一个
///   实例刚好在此刻拿到锁"和"心跳恰好在此刻刷新"的竞争窗口压到两次 stat 之间。
///
/// 这仍然是尽力而为，不是内核级别的保证：心跳是进程内的线程，进程整体被挂起
/// （挂起、休眠、调度饿死）超过门限时活锁仍可能被误回收；非 Unix 的生产部署应
/// 改用平台原生的独占文件锁（Windows 上是以 share_mode(0) 打开锁文件），而不是
/// 依赖本实现。测试时在所有平台编译，否则这段逻辑在 CI（Linux）上永远没人验证。
#[cfg(any(not(unix), test))]
mod directory_lock {
    use super::{ErrorKind, KEY_STORAGE_LOCK_FILE, Path, fs, io};
    use std::{
        path::PathBuf,
        sync::{Arc, Condvar, Mutex, MutexGuard},
        thread::{self, JoinHandle},
        time::{Duration, SystemTime},
    };

    /// 记录持锁进程 pid 的文件，位于锁目录内部。
    const LOCK_OWNER_FILE: &str = "owner";

    /// 超过这个年龄且不属于本进程的锁判定为崩溃遗留。
    ///
    /// 年龄从最后一次心跳（owner 文件的 mtime）算起，是 [`HEARTBEAT_INTERVAL`]
    /// 的 12 倍：活锁持有者每 5 秒刷新一次心跳，持锁多久都不会被误伤；崩溃遗留
    /// 的锁在进程死亡后最多阻塞一分钟，而不是永远。
    const STALE_LOCK_AGE: Duration = Duration::from_secs(60);

    /// 持锁期间心跳刷新的间隔：周期性重写 owner 文件，把"最后一次心跳"刻进 mtime。
    ///
    /// 必须远小于 [`STALE_LOCK_AGE`]（这里是 12 倍余量），偶尔错过一两次心跳的
    /// 调度抖动不能把活锁误判成崩溃遗留。
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

    /// 阻塞获取时等待活锁的上限。
    const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

    /// 轮询间隔。
    const RETRY_INTERVAL: Duration = Duration::from_millis(10);

    /// 非 Unix 平台持有的锁：锁目录路径 + 证明本进程存活的心跳线程。
    ///
    /// 释放必须显式调用 [`DirectoryLock::release`]（`KeyStorageLock` 的 Drop 会
    /// 做）；直接 drop 只停掉心跳线程，锁目录留在盘上等陈旧回收。
    #[derive(Debug)]
    pub(super) struct DirectoryLock {
        path: PathBuf,
        heartbeat: Heartbeat,
    }

    impl DirectoryLock {
        pub(super) fn path(&self) -> &Path {
            &self.path
        }

        /// 释放锁：先停掉心跳，再删除锁目录。顺序不能反——心跳线程在目录删除后
        /// 仍可能再写一次 owner 文件，把旧 pid 写进后继实例刚建好的锁目录。
        pub(super) fn release(&mut self) {
            self.heartbeat.stop();
            let _ = fs::remove_file(self.path.join(LOCK_OWNER_FILE));
            let _ = fs::remove_dir(&self.path);
        }
    }

    /// 一次对锁目录归属信息的观测。
    ///
    /// `owner` 为 `None` 表示 pid 未知：`owner` 文件缺失或内容无法解析，通常是
    /// 崩溃发生在"建目录"与"写 pid"之间。此时只按年龄判断，不因为读不到 pid
    /// 就把锁当成活的（那会退化成永久阻塞），也不因此立刻回收。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct ObservedLock {
        owner: Option<u32>,
        last_heartbeat: Option<SystemTime>,
    }

    /// 获取锁目录：成功时返回持锁句柄；崩溃遗留的锁会被回收后重试。
    pub(super) fn acquire(directory: &Path, blocking: bool) -> io::Result<DirectoryLock> {
        acquire_with_heartbeat(directory, blocking, HEARTBEAT_INTERVAL)
    }

    /// 带自定义心跳间隔的获取实现：生产路径由 [`acquire`] 固定为
    /// [`HEARTBEAT_INTERVAL`]，测试用短间隔验证心跳机制而不必真实等待。
    fn acquire_with_heartbeat(
        directory: &Path,
        blocking: bool,
        heartbeat_interval: Duration,
    ) -> io::Result<DirectoryLock> {
        let path = directory.join(KEY_STORAGE_LOCK_FILE);
        let deadline = SystemTime::now() + ACQUIRE_TIMEOUT;
        loop {
            match fs::create_dir(&path) {
                Ok(()) => {
                    write_owner(&path);
                    let heartbeat = Heartbeat::start(
                        path.join(LOCK_OWNER_FILE),
                        std::process::id().to_string(),
                        heartbeat_interval,
                    );
                    return Ok(DirectoryLock { path, heartbeat });
                }
                Err(error) if error.kind() != ErrorKind::AlreadyExists => return Err(error),
                Err(error) => {
                    // 先判陈旧：崩溃遗留的锁必须能在非阻塞路径上也被回收，否则
                    // 后台同步会把"永久残留"一直报成锁竞争，密钥永不收敛。
                    if reclaim_if_stale(&path, SystemTime::now())? {
                        continue;
                    }
                    if !blocking || SystemTime::now() >= deadline {
                        return Err(error);
                    }
                    std::thread::sleep(RETRY_INTERVAL);
                }
            }
        }
    }

    /// 写入持锁 pid。失败不影响互斥，只让后续观测把 owner 视为未知；这也是
    /// 持锁期间的第一拍心跳。
    fn write_owner(path: &Path) {
        let _ = fs::write(path.join(LOCK_OWNER_FILE), std::process::id().to_string());
    }

    /// 心跳线程：持锁期间周期性重写 owner 文件，把"最后一次心跳"刻进 mtime。
    ///
    /// 没有心跳，陈旧判据就只能看"持锁开始时刻"——慢文件系统、大密钥集下活锁
    /// 持锁超过 [`STALE_LOCK_AGE`] 就会被另一个实例回收，互斥失效（Issue #355）。
    #[derive(Debug)]
    pub(super) struct Heartbeat {
        shared: Arc<HeartbeatShared>,
        thread: Option<JoinHandle<()>>,
    }

    impl Heartbeat {
        /// 启动心跳线程。`interval` 由 [`acquire`] 固定为 [`HEARTBEAT_INTERVAL`]，
        /// 测试传短间隔验证机制。
        pub(super) fn start(owner_path: PathBuf, owner_id: String, interval: Duration) -> Self {
            let shared = Arc::new(HeartbeatShared {
                stop: Mutex::new(false),
                condvar: Condvar::new(),
                owner_path,
                owner_id,
                interval,
            });
            let worker = Arc::clone(&shared);
            let thread = thread::spawn(move || heartbeat_loop(&worker));
            Self {
                shared,
                thread: Some(thread),
            }
        }

        /// 通知心跳线程停止并等待其退出。幂等：第二次调用立即返回。
        pub(super) fn stop(&mut self) {
            {
                let mut guard = poison_tolerant_lock(&self.shared.stop);
                *guard = true;
            }
            self.shared.condvar.notify_all();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    impl Drop for Heartbeat {
        fn drop(&mut self) {
            // 兜底：句柄未走 release 路径（如测试直接丢弃）时也必须停掉线程，
            // 否则它会继续向可能已易主的锁目录写旧 pid。
            self.stop();
        }
    }

    #[derive(Debug)]
    struct HeartbeatShared {
        stop: Mutex<bool>,
        condvar: Condvar,
        owner_path: PathBuf,
        owner_id: String,
        interval: Duration,
    }

    fn heartbeat_loop(shared: &HeartbeatShared) {
        loop {
            let stop = {
                let guard = poison_tolerant_lock(&shared.stop);
                if *guard {
                    true
                } else {
                    let (guard, _) = shared
                        .condvar
                        .wait_timeout(guard, shared.interval)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *guard
                }
            };
            if stop {
                return;
            }
            // 刷新心跳：写 owner 文件会更新其 mtime，向其他实例证明本进程活着。
            // 失败忽略：锁目录已被释放或文件系统错误都不该让持锁进程崩溃。
            let _ = fs::write(&shared.owner_path, &shared.owner_id);
        }
    }

    /// 容忍中毒互斥锁：心跳线程不能因为主线程 panic 而一起死掉，锁的活性证明
    /// 必须坚持到进程终止或锁被显式释放。
    fn poison_tolerant_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 判定并回收崩溃遗留的锁。返回 `true` 表示锁目录已被删除，调用方可重试创建。
    ///
    /// 判据是"不是本进程"且"超过 [`STALE_LOCK_AGE`] 没有心跳"：活锁持有者的心跳
    /// 线程每 [`HEARTBEAT_INTERVAL`] 刷新一次 owner 文件 mtime，持锁多久都不会
    /// 被误判（Issue #355）。
    pub(super) fn reclaim_if_stale(path: &Path, now: SystemTime) -> io::Result<bool> {
        let observed = observe(path)?;
        if !is_stale(observed, std::process::id(), now) {
            return Ok(false);
        }
        // 删除前重新观测：pid 或心跳时间变了说明这把锁已经换了主人（前一个持锁者
        // 释放、另一个实例刚拿到）或心跳恰好在此刻刷新，此时删除等于抢走一把活锁。
        if observe(path)? != observed {
            return Ok(false);
        }
        tracing::warn!(
            lock_path = %path.display(),
            "reclaiming a stale key storage lock left by a crashed process"
        );
        let _ = fs::remove_file(path.join(LOCK_OWNER_FILE));
        match fs::remove_dir(path) {
            Ok(()) => Ok(true),
            // 删不掉就当作"这轮没回收成功"：可能是另一个实例已经重建了锁并写好
            // owner 文件（目录非空），也可能是它已经被别人删掉了。两种情况都按
            // 活锁继续重试，绝不因为删除失败就去删更多东西。
            Err(_) => Ok(false),
        }
    }

    /// 读取锁目录的归属信息；锁不存在时返回 `None` 观测。
    fn observe(path: &Path) -> io::Result<ObservedLock> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(ObservedLock {
                    owner: None,
                    last_heartbeat: None,
                });
            }
            Err(error) => return Err(error),
        };
        // 锁路径被换成普通文件或符号链接：目录已被篡改，fail-closed。
        if !metadata.is_dir() {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "invalid secure storage path",
            ));
        }

        let owner_path = path.join(LOCK_OWNER_FILE);
        let owner = fs::read_to_string(&owner_path)
            .ok()
            .and_then(|contents| contents.trim().parse::<u32>().ok());
        // 最后一次心跳优先取 owner 文件的 mtime：它是普通文件，各平台都能稳定
        // 读到，且持锁者每 `HEARTBEAT_INTERVAL` 重写一次。owner 文件缺失时退回
        // 目录自身的 mtime（崩溃发生在写 pid 之前）。
        let last_heartbeat = fs::metadata(&owner_path)
            .or_else(|_| fs::metadata(path))
            .and_then(|metadata| metadata.modified())
            .ok();
        Ok(ObservedLock {
            owner,
            last_heartbeat,
        })
    }

    /// 陈旧判据：既不属于本进程，又已超过 [`STALE_LOCK_AGE`] 没有心跳。
    ///
    /// 拆成纯函数是为了能在 Unix 上单测——生产路径在 Unix 走 flock，这段逻辑
    /// 否则永远得不到验证。
    pub(super) fn is_stale(observed: ObservedLock, current_pid: u32, now: SystemTime) -> bool {
        let Some(last_heartbeat) = observed.last_heartbeat else {
            // 锁目录不存在：没有可回收的对象。
            return false;
        };
        if observed.owner == Some(current_pid) {
            return false;
        }
        // 最后一次心跳晚于 now（时钟回拨或跨主机的共享目录）按活锁处理：宁可多等
        // 一个超时窗口，也不能因为时间对不上就抢走别人的锁。
        now.duration_since(last_heartbeat)
            .is_ok_and(|age| age >= STALE_LOCK_AGE)
    }

    #[cfg(test)]
    pub(super) fn observed_for_test(
        owner: Option<u32>,
        last_heartbeat: Option<SystemTime>,
    ) -> ObservedLock {
        ObservedLock {
            owner,
            last_heartbeat,
        }
    }

    #[cfg(test)]
    pub(super) fn stale_lock_age() -> Duration {
        STALE_LOCK_AGE
    }

    #[cfg(test)]
    pub(super) fn owner_file(path: &Path) -> PathBuf {
        path.join(LOCK_OWNER_FILE)
    }
}

#[cfg(test)]
#[path = "key_lock_tests.rs"]
mod tests;
