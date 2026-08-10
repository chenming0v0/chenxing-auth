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
/// 表达互斥，并额外承担 Unix 上由内核免费提供的那件事——识别崩溃遗留的锁。
pub(crate) struct KeyStorageLock {
    #[cfg(unix)]
    file: File,
    #[cfg(not(unix))]
    path: std::path::PathBuf,
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
            let path = directory_lock::acquire(directory, true)?;
            Ok(Self { path })
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
            let path = directory_lock::acquire(directory, false)?;
            Ok(Self { path })
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
        directory_lock::release(&self.path);
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
/// 因此这里给锁目录附一份归属信息：`owner` 文件记录持锁进程的 pid，文件 mtime
/// 记录持锁开始的时间。两者同时满足"不是本进程"和"超过 `STALE_LOCK_AGE`"时，
/// 判定为崩溃遗留并回收。判据刻意保守：
///
/// - pid 相同一律视为活锁。同进程重入拿不到锁是既有语义（Unix 上 flock 的
///   归属是 open file description，同进程不同 fd 同样互斥），不能因为"看起来
///   很旧"就放行。
/// - 时间未到一律视为活锁。持锁区间是一次密钥目录读写，正常在毫秒级，
///   60 秒的门限比任何合理的持锁时长高几个数量级。
/// - 回收前重新观测一次归属信息，只在 pid 与 mtime 都没变过时才删。这把"另一个
///   实例刚好在此刻拿到锁"的竞争窗口压到两次 stat 之间。
///
/// 这仍然是尽力而为，不是内核级别的保证：非 Unix 的生产部署应改用平台原生的
/// 独占文件锁（Windows 上是以 share_mode(0) 打开锁文件），而不是依赖本实现。
/// 测试时在所有平台编译，否则这段逻辑在 CI（Linux）上永远没人验证。
#[cfg(any(not(unix), test))]
mod directory_lock {
    use super::{ErrorKind, KEY_STORAGE_LOCK_FILE, Path, fs, io};
    use std::{
        path::PathBuf,
        time::{Duration, SystemTime},
    };

    /// 记录持锁进程 pid 的文件，位于锁目录内部。
    const LOCK_OWNER_FILE: &str = "owner";

    /// 超过这个年龄且不属于本进程的锁判定为崩溃遗留。
    ///
    /// 持锁区间是一次密钥目录读写（毫秒级），门限高出几个数量级，因此不会误伤
    /// 正常持锁；同时保证崩溃遗留的锁最多阻塞一分钟，而不是永远。
    const STALE_LOCK_AGE: Duration = Duration::from_secs(60);

    /// 阻塞获取时等待活锁的上限。
    const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

    /// 轮询间隔。
    const RETRY_INTERVAL: Duration = Duration::from_millis(10);

    /// 一次对锁目录归属信息的观测。
    ///
    /// `owner` 为 `None` 表示 pid 未知：`owner` 文件缺失或内容无法解析，通常是
    /// 崩溃发生在"建目录"与"写 pid"之间。此时只按年龄判断，不因为读不到 pid
    /// 就把锁当成活的（那会退化成永久阻塞），也不因此立刻回收。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct ObservedLock {
        owner: Option<u32>,
        held_since: Option<SystemTime>,
    }

    pub(super) fn acquire(directory: &Path, blocking: bool) -> io::Result<PathBuf> {
        let path = directory.join(KEY_STORAGE_LOCK_FILE);
        let deadline = SystemTime::now() + ACQUIRE_TIMEOUT;
        loop {
            match fs::create_dir(&path) {
                Ok(()) => {
                    write_owner(&path);
                    return Ok(path);
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

    pub(super) fn release(path: &Path) {
        let _ = fs::remove_file(path.join(LOCK_OWNER_FILE));
        let _ = fs::remove_dir(path);
    }

    /// 写入持锁 pid。失败不影响互斥，只让后续观测把 owner 视为未知。
    fn write_owner(path: &Path) {
        let _ = fs::write(path.join(LOCK_OWNER_FILE), std::process::id().to_string());
    }

    /// 判定并回收崩溃遗留的锁。返回 `true` 表示锁目录已被删除，调用方可重试创建。
    pub(super) fn reclaim_if_stale(path: &Path, now: SystemTime) -> io::Result<bool> {
        let observed = observe(path)?;
        if !is_stale(observed, std::process::id(), now) {
            return Ok(false);
        }
        // 删除前重新观测：pid 或起始时间变了说明这把锁已经换了主人（前一个持锁者
        // 释放、另一个实例刚拿到），此时删除等于抢走一把活锁。
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
                    held_since: None,
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
        // 起始时间优先取 owner 文件的 mtime：它在建目录后立即写入，且是普通文件，
        // 各平台都能稳定读到。owner 文件缺失时退回目录自身的 mtime。
        let held_since = fs::metadata(&owner_path)
            .or_else(|_| fs::metadata(path))
            .and_then(|metadata| metadata.modified())
            .ok();
        Ok(ObservedLock { owner, held_since })
    }

    /// 陈旧判据：既不属于本进程，又已超过 `STALE_LOCK_AGE`。
    ///
    /// 拆成纯函数是为了能在 Unix 上单测——生产路径在 Unix 走 flock，这段逻辑
    /// 否则永远得不到验证。
    pub(super) fn is_stale(observed: ObservedLock, current_pid: u32, now: SystemTime) -> bool {
        let Some(held_since) = observed.held_since else {
            // 锁目录不存在：没有可回收的对象。
            return false;
        };
        if observed.owner == Some(current_pid) {
            return false;
        }
        // 起始时间晚于 now（时钟回拨或跨主机的共享目录）按活锁处理：宁可多等
        // 一个超时窗口，也不能因为时间对不上就抢走别人的锁。
        now.duration_since(held_since)
            .is_ok_and(|age| age >= STALE_LOCK_AGE)
    }

    #[cfg(test)]
    pub(super) fn observed_for_test(
        owner: Option<u32>,
        held_since: Option<SystemTime>,
    ) -> ObservedLock {
        ObservedLock { owner, held_since }
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
