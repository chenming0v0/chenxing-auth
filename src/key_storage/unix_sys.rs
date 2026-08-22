//! Unix 密钥目录的 dirfd 系统调用封装。
//!
//! Linux 优先 `openat2`；老内核或非 Linux 回退 `openat` + `O_NOFOLLOW`。
//! 绝对路径走查不用 `RESOLVE_BENEATH`（`/tmp/...` 相对 AT_FDCWD/`/` 不在
//! cwd 之下）；已验证目录内的单分量才用 BENEATH。

use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::ffi::OsStrExt,
    },
    ptr::NonNull,
};

use super::policy::invalid_storage_path;

#[cfg(target_os = "linux")]
use std::ffi::CStr;

/// openat2 的 resolve 范围。
#[derive(Clone, Copy)]
pub(super) enum OpenScope {
    /// 已持有密钥目录内的单分量：必须落在 dirfd 之下。
    Child,
    /// 绝对路径分量、`/` / `.` 起点、或祖先 `..`：禁止跟随符号链接，不要求 beneath。
    Path,
}

impl OpenScope {
    #[cfg(target_os = "linux")]
    fn resolve_flags(self) -> u64 {
        let no_links = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
        match self {
            Self::Child => no_links | libc::RESOLVE_BENEATH,
            Self::Path => no_links,
        }
    }
}

pub(super) fn open_beneath(
    dirfd: RawFd,
    name: &OsStr,
    flags: libc::c_int,
    mode: u32,
) -> io::Result<File> {
    validate_basename(name)?;
    open_at(dirfd, name, flags, mode, OpenScope::Child)
}

/// 打开 `/`、`.`、`..` 或绝对路径走查的单分量。不套 BENEATH。
pub(super) fn open_path_component(
    dirfd: RawFd,
    name: &OsStr,
    flags: libc::c_int,
    mode: u32,
) -> io::Result<File> {
    validate_path_component(name)?;
    open_at(dirfd, name, flags, mode, OpenScope::Path)
}

fn open_at(
    dirfd: RawFd,
    name: &OsStr,
    flags: libc::c_int,
    mode: u32,
    scope: OpenScope,
) -> io::Result<File> {
    let c_name = to_c_string(name)?;
    let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    #[cfg(target_os = "linux")]
    {
        match openat2_with(dirfd, &c_name, flags, mode, scope.resolve_flags()) {
            Ok(file) => return Ok(file),
            Err(error) if fallback_to_openat(&error) => {}
            Err(error) => return Err(map_open_error(error)),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = scope;
    }
    // SAFETY: dirfd 是活目录或 AT_FDCWD；c_name 是有效 C 字符串。
    let fd = unsafe { libc::openat(dirfd, c_name.as_ptr(), flags, mode as libc::c_uint) };
    from_file_fd(fd)
}

#[cfg(target_os = "linux")]
fn openat2_with(
    dirfd: RawFd,
    name: &CStr,
    flags: libc::c_int,
    mode: u32,
    resolve: u64,
) -> io::Result<File> {
    // SAFETY: open_how 是 non_exhaustive，不能写结构体字面量。全部字段都是
    // 整数，全 0 是合法位型，也是 openat2 对未知/未用字段的约定值；随后只写入
    // 本内核 ABI 已文档化的 flags/mode/resolve。
    let mut how = unsafe { std::mem::zeroed::<libc::open_how>() };
    how.flags = flags as u64;
    how.mode = u64::from(mode);
    how.resolve = resolve;
    // SAFETY: how 指向本栈上的 open_how；name 是有效 C 字符串。
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            name.as_ptr(),
            std::ptr::addr_of!(how),
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    from_file_fd(fd as RawFd)
}

#[cfg(target_os = "linux")]
fn fallback_to_openat(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
    )
}

pub(super) fn from_file_fd(fd: RawFd) -> io::Result<File> {
    if fd < 0 {
        return Err(map_open_error(io::Error::last_os_error()));
    }
    // SAFETY: fd 刚从成功的 open/openat 返回，所有权交给 File。
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn mkdirat(dirfd: RawFd, name: &OsStr, mode: u32) -> io::Result<()> {
    validate_basename(name)?;
    let c_name = to_c_string(name)?;
    // SAFETY: 单分量名；已有目录 fd。
    let result = unsafe { libc::mkdirat(dirfd, c_name.as_ptr(), mode as libc::mode_t) };
    cvt(result)
}

pub(super) fn unlinkat(dirfd: RawFd, name: &str) -> io::Result<()> {
    let c_name = to_c_string(OsStr::new(name))?;
    let result = unsafe { libc::unlinkat(dirfd, c_name.as_ptr(), 0) };
    cvt(result)
}

pub(super) fn renameat(dirfd: RawFd, from: &str, to: &str) -> io::Result<()> {
    let from = to_c_string(OsStr::new(from))?;
    let to = to_c_string(OsStr::new(to))?;
    let result = unsafe { libc::renameat(dirfd, from.as_ptr(), dirfd, to.as_ptr()) };
    cvt(result)
}

pub(super) fn linkat(dirfd: RawFd, from: &str, to: &str) -> io::Result<()> {
    let from = to_c_string(OsStr::new(from))?;
    let to = to_c_string(OsStr::new(to))?;
    let result = unsafe { libc::linkat(dirfd, from.as_ptr(), dirfd, to.as_ptr(), 0) };
    cvt(result)
}

pub(super) fn fchmod(file: &File, mode: u32) -> io::Result<()> {
    let result = unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) };
    cvt(result)
}

/// POSIX `readdir`：调用前清 errno。NULL + errno 0 是 EOF；EINTR 重试；
/// 其余错误失败。不得把已读到的前缀当成完整清单。
pub(super) fn readdir(dirp: *mut libc::DIR) -> io::Result<Option<NonNull<libc::dirent>>> {
    loop {
        #[cfg(test)]
        if let Some(errno) = readdir_test::take_fault() {
            if errno == libc::EINTR {
                continue;
            }
            return Err(io::Error::from_raw_os_error(errno));
        }

        #[cfg(test)]
        if let Some(errno) = readdir_test::stale_errno_value() {
            set_errno(errno);
        }
        // POSIX：readdir 前必须把 errno 置 0。NULL + 0 才是 EOF；NULL + 非 0 是错误。
        set_errno(0);

        // SAFETY: dirp 来自 fdopendir，且尚未 closedir。
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            let errno = current_errno();
            if errno == 0 {
                return Ok(None);
            }
            if errno == libc::EINTR {
                continue;
            }
            return Err(io::Error::from_raw_os_error(errno));
        }
        #[cfg(test)]
        readdir_test::record_success();
        // SAFETY: readdir 成功时返回非空 dirent，有效直到下次 readdir/closedir。
        return Ok(Some(unsafe { NonNull::new_unchecked(entry) }));
    }
}

fn validate_basename(name: &OsStr) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(invalid_storage_path());
    }
    let bytes = name.as_bytes();
    if bytes.contains(&b'/') || bytes.contains(&0) {
        return Err(invalid_storage_path());
    }
    Ok(())
}

fn validate_path_component(name: &OsStr) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(invalid_storage_path());
    }
    let special = name == "/" || name == "." || name == "..";
    if !special && bytes.contains(&b'/') {
        return Err(invalid_storage_path());
    }
    Ok(())
}

pub(super) fn to_c_string(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes().to_vec()).map_err(|_| invalid_storage_path())
}

pub(super) fn map_open_error(error: io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR | libc::EPERM) => invalid_storage_path(),
        _ => error,
    }
}

fn cvt(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(map_open_error(io::Error::last_os_error()))
    }
}

fn set_errno(value: i32) {
    // SAFETY: errno 是线程局部的；写入当前线程的 errno 单元。
    unsafe {
        *errno_ptr() = value;
    }
}

fn current_errno() -> i32 {
    // SAFETY: 读取当前线程 errno。
    unsafe { *errno_ptr() }
}

fn errno_ptr() -> *mut libc::c_int {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: __errno_location 返回当前线程 errno 的指针。
        unsafe { libc::__errno_location() }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // SAFETY: __error 返回当前线程 errno 的指针。
        unsafe { libc::__error() }
    }
}

#[cfg(test)]
pub(super) mod readdir_test {
    use std::cell::Cell;

    thread_local! {
        static FAULT: Cell<Option<(u32, i32)>> = const { Cell::new(None) };
        static SUCCESSES: Cell<u32> = const { Cell::new(0) };
        static STALE_ERRNO: Cell<Option<i32>> = const { Cell::new(None) };
    }

    pub struct FaultGuard {
        _private: (),
    }

    impl Drop for FaultGuard {
        fn drop(&mut self) {
            clear();
        }
    }

    pub fn fail_after(successes: u32, errno: i32) -> FaultGuard {
        clear();
        FAULT.set(Some((successes, errno)));
        FaultGuard { _private: () }
    }

    pub fn stale_errno(errno: i32) -> FaultGuard {
        clear();
        STALE_ERRNO.set(Some(errno));
        FaultGuard { _private: () }
    }

    pub(super) fn take_fault() -> Option<i32> {
        let (after, errno) = FAULT.get()?;
        if SUCCESSES.get() < after {
            return None;
        }
        FAULT.set(None);
        Some(errno)
    }

    pub(super) fn record_success() {
        SUCCESSES.set(SUCCESSES.get() + 1);
    }

    pub(super) fn stale_errno_value() -> Option<i32> {
        STALE_ERRNO.get()
    }

    fn clear() {
        FAULT.set(None);
        SUCCESSES.set(0);
        STALE_ERRNO.set(None);
    }
}
