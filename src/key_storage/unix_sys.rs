//! Unix 密钥目录的 dirfd 系统调用封装。
//!
//! Linux 优先 `openat2`；老内核或非 Linux 回退 `openat` + `O_NOFOLLOW`。
//! 绝对路径走查不用 `RESOLVE_BENEATH`（`/tmp/...` 相对 AT_FDCWD/`/` 不在
//! cwd 之下）；已验证目录内的单分量才用 BENEATH。

use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::ffi::OsStrExt,
    },
};

use super::policy::invalid_storage_path;

/// openat2 的 resolve 范围。
#[derive(Clone, Copy)]
pub(super) enum OpenScope {
    /// 已持有密钥目录内的单分量：必须落在 dirfd 之下。
    Child,
    /// 绝对路径分量、`/` / `.` 起点、或祖先 `..`：禁止跟随符号链接，不要求 beneath。
    Path,
}

impl OpenScope {
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
    let fd = unsafe { libc::openat(dirfd, c_name.as_ptr(), flags, mode as libc::mode_t) };
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
