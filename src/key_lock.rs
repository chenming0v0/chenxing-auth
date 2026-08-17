#[cfg(any(unix, windows))]
use std::fs::File;
use std::{io, path::Path};

const KEY_STORAGE_LOCK_FILE: &str = ".chenxing-key.lock";

/// 共享密钥目录的进程级互斥锁。
///
/// Unix 使用内核 `flock`；Windows 以 `share_mode(0)` 打开长期存在的普通文件。
/// 两条路径都把所有权绑定到内核句柄：进程退出会自动释放，进程暂停不会让锁过期，
/// PID、mtime 与文件内容都不参与 fencing。释放只关闭句柄，绝不删除 Windows 锁路径。
/// 其它平台保留带 fencing token 与 heartbeat 的目录回退，兼容 Issue #355。
#[derive(Debug)]
pub(crate) struct KeyStorageLock {
    #[cfg(unix)]
    file: File,
    #[cfg(windows)]
    _file: File,
    #[cfg(not(any(unix, windows)))]
    lock: directory_lock::DirectoryLock,
}

impl KeyStorageLock {
    pub(crate) fn acquire(directory: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let file = unix_lock::open(directory)?;
            unix_lock::lock(&file, false)?;
            return Ok(Self { file });
        }

        #[cfg(windows)]
        {
            return windows_lock::acquire(directory, true).map(|file| Self { _file: file });
        }

        #[cfg(not(any(unix, windows)))]
        {
            let lock = directory_lock::acquire(directory, true)?;
            return Ok(Self { lock });
        }
    }

    pub(crate) fn try_acquire(directory: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let file = unix_lock::open(directory)?;
            unix_lock::lock(&file, true)?;
            return Ok(Self { file });
        }

        #[cfg(windows)]
        {
            return windows_lock::acquire(directory, false).map(|file| Self { _file: file });
        }

        #[cfg(not(any(unix, windows)))]
        {
            let lock = directory_lock::acquire(directory, false)?;
            return Ok(Self { lock });
        }
    }
}

#[cfg(unix)]
mod unix_lock {
    use std::{ffi::c_int, fs::File, io, os::fd::AsRawFd, path::Path};

    use super::KEY_STORAGE_LOCK_FILE;
    use crate::key_storage::open_or_create_regular_file;

    const LOCK_EX: c_int = 2;
    const LOCK_NB: c_int = 4;
    const LOCK_UN: c_int = 8;

    unsafe extern "C" {
        fn flock(fd: c_int, operation: c_int) -> c_int;
    }

    pub(super) fn open(directory: &Path) -> io::Result<File> {
        open_or_create_regular_file(directory, KEY_STORAGE_LOCK_FILE)
    }

    pub(super) fn lock(file: &File, nonblocking: bool) -> io::Result<()> {
        let operation = LOCK_EX | if nonblocking { LOCK_NB } else { 0 };
        if unsafe { flock(file.as_raw_fd(), operation) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn unlock(file: &File) {
        let _ = unsafe { flock(file.as_raw_fd(), LOCK_UN) };
    }
}

#[cfg(unix)]
impl Drop for KeyStorageLock {
    fn drop(&mut self) {
        unix_lock::unlock(&self.file);
    }
}

#[cfg(not(any(unix, windows)))]
impl Drop for KeyStorageLock {
    fn drop(&mut self) {
        self.lock.release();
    }
}

#[cfg(windows)]
mod windows_lock {
    use std::{
        fs::{File, OpenOptions},
        io::{self, ErrorKind},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
        thread,
        time::{Duration, Instant},
    };

    use super::KEY_STORAGE_LOCK_FILE;

    const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
    const RETRY_INTERVAL: Duration = Duration::from_millis(10);
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;

    pub(super) fn acquire(directory: &Path, blocking: bool) -> io::Result<File> {
        let path = directory.join(KEY_STORAGE_LOCK_FILE);
        let deadline = Instant::now() + ACQUIRE_TIMEOUT;
        loop {
            match open_exclusive(&path) {
                Ok(file) => return Ok(file),
                Err(error) if error.kind() == ErrorKind::WouldBlock && blocking => {
                    if Instant::now() >= deadline {
                        return Err(error);
                    }
                    thread::sleep(RETRY_INTERVAL);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn open_exclusive(path: &Path) -> io::Result<File> {
        reject_non_regular_existing_path(path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(map_contention)?;
        require_regular_handle(&file)?;
        Ok(file)
    }

    fn reject_non_regular_existing_path(path: &Path) -> io::Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && !is_reparse(&metadata) => Ok(()),
            Ok(_) => Err(invalid_lock_path()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(map_contention(error)),
        }
    }

    fn require_regular_handle(file: &File) -> io::Result<()> {
        let metadata = file.metadata()?;
        if metadata.is_file() && !is_reparse(&metadata) {
            Ok(())
        } else {
            Err(invalid_lock_path())
        }
    }

    fn is_reparse(metadata: &std::fs::Metadata) -> bool {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    fn invalid_lock_path() -> io::Error {
        io::Error::new(
            ErrorKind::PermissionDenied,
            "invalid secure storage lock path",
        )
    }

    fn map_contention(error: io::Error) -> io::Error {
        if matches!(
            error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION)
        ) {
            io::Error::new(ErrorKind::WouldBlock, "key storage lock is already held")
        } else {
            error
        }
    }
}

/// Portable fallback for targets without a standard kernel lock.
///
/// Windows uses the handle-backed path above. Other non-Unix targets retain the fenced
/// directory lease, and tests compile it on every platform to preserve Issue #355 coverage.
#[cfg(any(not(any(unix, windows)), test))]
#[path = "key_lock_directory.rs"]
mod directory_lock;
#[cfg(test)]
#[path = "key_lock_tests.rs"]
mod tests;
