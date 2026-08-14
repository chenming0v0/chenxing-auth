//! 密钥目录的安全文件原语。
//!
//! Unix 上所有关键操作绑定目录 fd：校验 owner 有效 uid 与祖先权限，
//! `openat2`/`openat` + `O_NOFOLLOW` 打开后再 `fstat` 同一 inode。
//! 非 Unix 没有 POSIX owner / `O_NOFOLLOW`，保持路径级 create + 读写语义，
//! 不假装做了同等检查。

use std::{
    fs::File,
    io::{self, ErrorKind},
    path::Path,
    time::SystemTime,
};

#[cfg(not(unix))]
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
};

#[cfg(not(unix))]
use uuid::Uuid;

#[path = "../key_lock.rs"]
mod key_lock;
pub(crate) use key_lock::KeyStorageLock;

mod policy;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
mod unix_sys;

#[cfg(all(test, unix))]
#[path = "tests.rs"]
mod tests;

pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;
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
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

pub(crate) fn remove_secure_file(path: &Path) -> io::Result<()> {
    with_parent(path, |_, name| {
        #[cfg(unix)]
        {
            unix::SecureDir::open(path.parent().ok_or_else(invalid_storage_path)?)?
                .remove_regular_file(name)
        }
        #[cfg(not(unix))]
        {
            fs::remove_file(path)
        }
    })
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
    #[cfg(not(unix))]
    {
        fallback_atomic_write(kind, path, contents, replace_existing)
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
    #[cfg(not(unix))]
    {
        let _ = expected;
        let path = directory.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() {
            return Err(invalid_storage_path());
        }
        let mut file = File::open(&path)?;
        let modified = file.metadata()?.modified()?;
        let mut contents = Vec::new();
        match max_bytes {
            Some(limit) => {
                file.take(limit.saturating_add(1))
                    .read_to_end(&mut contents)?;
            }
            None => {
                file.read_to_end(&mut contents)?;
            }
        }
        Ok(SecureFileData { contents, modified })
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
    #[cfg(not(unix))]
    {
        let mut names = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            names.push(SecureDirEntry { name, inode: None });
        }
        Ok(names)
    }
}

/// 普通文件存在为 `true`，缺失为 `false`；符号链接/目录/异主一律报错。
pub(crate) fn inspect_secure_file(path: &Path) -> io::Result<bool> {
    let (parent, name) = split_dir_and_name(path)?;
    #[cfg(unix)]
    {
        unix::SecureDir::open(parent)?.inspect_regular_file(name)
    }
    #[cfg(not(unix))]
    {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => Ok(true),
            Ok(_) => Err(invalid_storage_path()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

pub(crate) fn open_or_create_regular_file(directory: &Path, name: &str) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix::SecureDir::open(directory)?.open_or_create(name)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(directory.join(name))
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

fn split_dir_and_name(path: &Path) -> io::Result<(&Path, &str)> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid_storage_path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    Ok((parent.unwrap_or_else(|| Path::new(".")), name))
}

fn with_parent<T>(path: &Path, op: impl FnOnce(&Path, &str) -> io::Result<T>) -> io::Result<T> {
    let (parent, name) = split_dir_and_name(path)?;
    op(parent, name)
}

fn is_temporary_file(file_name: &str, kind: TemporaryFileKind) -> bool {
    file_name
        .strip_prefix(kind.prefix())
        .and_then(|name| name.strip_suffix(TEMPORARY_FILE_SUFFIX))
        .is_some_and(|unique| !unique.is_empty())
}

#[cfg(not(unix))]
fn fallback_atomic_write(
    kind: TemporaryFileKind,
    path: &Path,
    contents: &[u8],
    replace_existing: bool,
) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(invalid_storage_path()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = path.parent().ok_or_else(invalid_storage_path)?;
    let temporary = parent.join(format!(
        "{}{}{TEMPORARY_FILE_SUFFIX}",
        kind.prefix(),
        Uuid::new_v4().simple()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        if replace_existing {
            fs::rename(&temporary, path)?;
        } else {
            fs::hard_link(&temporary, path)?;
            let _ = fs::remove_file(&temporary);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
