//! 密钥目录的安全文件原语。
//!
//! Unix 上所有关键操作绑定目录 fd：校验 owner 有效 uid 与祖先权限，
//! `openat2`/`openat` + `O_NOFOLLOW` 打开后再 `fstat` 同一 inode。
//! Windows 上等价边界是受保护 DACL 与 `NtCreateFile` + `FILE_OPEN_REPARSE_POINT`：
//! 叶子只授给当前进程/服务帐户和 SYSTEM，重解析点与宽松/外来 ACL fail-closed。
//! 其它目标没有这套原语，安全文件操作返回 `Unsupported`。

#[cfg(any(unix, windows))]
use std::fs::File;
use std::{
    io::{self, ErrorKind},
    path::Path,
    time::SystemTime,
};

#[path = "../key_lock.rs"]
mod key_lock;
pub(crate) use key_lock::KeyStorageLock;

#[cfg_attr(not(unix), allow(dead_code))]
mod policy;
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
mod windows_policy;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
mod unix_sys;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_acl;
#[cfg(windows)]
mod windows_sys;

#[cfg(not(any(unix, windows)))]
mod unsupported;

#[cfg(all(test, unix))]
#[path = "tests.rs"]
mod tests;

#[cfg(all(test, windows))]
#[path = "windows_tests.rs"]
mod windows_tests;

#[cfg(unix)]
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
pub(crate) const KEY_DIRECTORY_MODE: u32 = 0o700;
const TEMPORARY_FILE_SUFFIX: &str = ".tmp";

/// 原子写入临时文件的命名空间。
///
/// `KeyManager` 与 `SecretManager` 共享 `KEY_DIRECTORY`，但不能假设清理半成品时
/// 对方已经持有同一把目录锁。两个子系统使用互不重叠的前缀，各自只删除自己的
/// `.tmp`，这样一方正在写的临时文件不会被另一方当成崩溃残留清掉（Issue #458）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TemporaryFileKind {
    SigningKey,
    ProviderSecret,
}

impl TemporaryFileKind {
    const fn prefix(self) -> &'static str {
        match self {
            Self::SigningKey => ".chenxing-key-",
            Self::ProviderSecret => ".chenxing-secret-",
        }
    }
}

pub(crate) use policy::{FileInode, invalid_storage_path};

#[derive(Debug)]
pub(crate) struct SecureDirEntry {
    pub name: String,
    pub inode: Option<FileInode>,
}

#[derive(Debug)]
pub(crate) struct SecureFileData {
    pub contents: Vec<u8>,
    pub modified: SystemTime,
}

pub(crate) fn ensure_secure_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix::SecureDir::ensure(path).map(|_| ())
    }
    #[cfg(windows)]
    {
        windows::SecureDir::ensure(path).map(|_| ())
    }
    #[cfg(not(any(unix, windows)))]
    {
        unsupported::ensure_secure_directory(path)
    }
}

pub(crate) fn remove_secure_file(path: &Path) -> io::Result<()> {
    let (parent, name) = split_dir_and_name(path)?;
    #[cfg(unix)]
    {
        unix::SecureDir::open(parent)?.remove_regular_file(name)
    }
    #[cfg(windows)]
    {
        windows::SecureDir::open(parent)?.remove_regular_file(name)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name);
        unsupported::remove_secure_file(path)
    }
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8], replace_existing: bool) -> io::Result<()> {
    atomic_write_in(
        TemporaryFileKind::SigningKey,
        path,
        contents,
        replace_existing,
    )
}

pub(crate) fn atomic_write_in(
    kind: TemporaryFileKind,
    path: &Path,
    contents: &[u8],
    replace_existing: bool,
) -> io::Result<()> {
    let (parent, name) = split_dir_and_name(path)?;
    #[cfg(unix)]
    {
        unix::SecureDir::open(parent)?.atomic_write(kind, name, contents, replace_existing)
    }
    #[cfg(windows)]
    {
        windows::SecureDir::open(parent)?.atomic_write(kind, name, contents, replace_existing)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name, kind, contents, replace_existing);
        unsupported::atomic_write(path)
    }
}

pub(crate) fn cleanup_stale_temporary_files(directory: &Path) -> io::Result<()> {
    cleanup_stale_temporary_files_in(directory, TemporaryFileKind::SigningKey)
}

pub(crate) fn cleanup_stale_temporary_files_in(
    directory: &Path,
    kind: TemporaryFileKind,
) -> io::Result<()> {
    for entry in list_secure_names(directory)? {
        if is_temporary_file(&entry.name, kind) {
            remove_secure_file(&directory.join(&entry.name))?;
        }
    }
    Ok(())
}

pub(crate) fn modified_time(path: &Path) -> io::Result<SystemTime> {
    Ok(read_secure_named_at(path, None, None)?.modified)
}

pub(crate) fn read_secure_file(path: &Path) -> io::Result<Vec<u8>> {
    Ok(read_secure_named_at(path, None, None)?.contents)
}

pub(crate) fn read_secure_file_limited(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    Ok(read_secure_named_at(path, None, Some(max_bytes))?.contents)
}

pub(crate) fn read_secure_to_string(path: &Path) -> io::Result<String> {
    String::from_utf8(read_secure_file(path)?)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "secure storage file is not utf-8"))
}

pub(crate) fn read_secure_named(
    directory: &Path,
    name: &str,
    expected: Option<FileInode>,
) -> io::Result<SecureFileData> {
    read_secure_named_limited(directory, name, expected, None)
}

fn read_secure_named_limited(
    directory: &Path,
    name: &str,
    expected: Option<FileInode>,
    max_bytes: Option<u64>,
) -> io::Result<SecureFileData> {
    #[cfg(unix)]
    {
        unix::SecureDir::open(directory)?.read_named_limited(name, expected, max_bytes)
    }
    #[cfg(windows)]
    {
        windows::SecureDir::open(directory)?.read_named_limited(name, expected, max_bytes)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (expected, max_bytes, name);
        unsupported::read_secure_named(directory)
    }
}

pub(crate) fn list_secure_names(directory: &Path) -> io::Result<Vec<SecureDirEntry>> {
    #[cfg(unix)]
    {
        Ok(unix::SecureDir::open(directory)?
            .list()?
            .into_iter()
            .map(|entry| SecureDirEntry {
                name: entry.name,
                inode: Some(entry.inode),
            })
            .collect())
    }
    #[cfg(windows)]
    {
        Ok(windows::SecureDir::open(directory)?
            .list()?
            .into_iter()
            .map(|entry| SecureDirEntry {
                name: entry.name,
                inode: Some(entry.inode),
            })
            .collect())
    }
    #[cfg(not(any(unix, windows)))]
    {
        unsupported::list_secure_names(directory)
    }
}

/// 普通文件存在为 `true`，缺失为 `false`；符号链接/目录/异主一律报错。
pub(crate) fn inspect_secure_file(path: &Path) -> io::Result<bool> {
    let (parent, name) = split_dir_and_name(path)?;
    #[cfg(unix)]
    {
        unix::SecureDir::open(parent)?.inspect_regular_file(name)
    }
    #[cfg(windows)]
    {
        windows::SecureDir::open(parent)?.inspect_regular_file(name)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name);
        unsupported::inspect_secure_file(path)
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn open_or_create_regular_file(directory: &Path, name: &str) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix::SecureDir::open(directory)?.open_or_create(name)
    }
    #[cfg(windows)]
    {
        windows::SecureDir::open(directory)?.open_or_create(name)
    }
}

fn read_secure_named_at(
    path: &Path,
    expected: Option<FileInode>,
    max_bytes: Option<u64>,
) -> io::Result<SecureFileData> {
    let (parent, name) = split_dir_and_name(path)?;
    read_secure_named_limited(parent, name, expected, max_bytes)
}

pub(super) fn split_dir_and_name(path: &Path) -> io::Result<(&Path, &str)> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid_storage_path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    Ok((parent.unwrap_or_else(|| Path::new(".")), name))
}

fn is_temporary_file(file_name: &str, kind: TemporaryFileKind) -> bool {
    file_name
        .strip_prefix(kind.prefix())
        .and_then(|name| name.strip_suffix(TEMPORARY_FILE_SUFFIX))
        .is_some_and(|unique| !unique.is_empty())
}
