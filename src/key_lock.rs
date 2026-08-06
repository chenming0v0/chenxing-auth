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
            acquire_directory_lock(directory, true)
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
            acquire_directory_lock(directory, false)
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

#[cfg(not(unix))]
fn acquire_directory_lock(directory: &Path, blocking: bool) -> io::Result<KeyStorageLock> {
    let path = directory.join(KEY_STORAGE_LOCK_FILE);
    // 非 Unix 没有标准库级别的文件锁；有限等待后返回错误，避免崩溃遗留目录让实例永久阻塞。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match fs::create_dir(&path) {
            Ok(()) => return Ok(KeyStorageLock { path }),
            Err(error)
                if error.kind() == ErrorKind::AlreadyExists
                    && blocking
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(unix))]
impl Drop for KeyStorageLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}
