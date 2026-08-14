use std::{
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Write},
    path::Path,
};

use uuid::Uuid;

#[path = "key_lock.rs"]
mod key_lock;
pub(crate) use key_lock::KeyStorageLock;

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

pub(crate) fn ensure_secure_directory(path: &Path) -> io::Result<()> {
    create_restricted_directory(path)?;

    // symlink_metadata 不跟随符号链接：密钥目录被替换成指向别处的链接时必须拒绝，
    // 否则后续私钥会落到攻击者可控的位置。
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(invalid_storage_path());
    }

    // 这里的 chmod 只为已存在的目录兜底：DirBuilder 的 mode 仅作用于它亲手创建的目录，
    // 对早先以宽松权限建好的目录，recursive 模式会直接返回 Ok 而不修正权限。
    // 新建路径在 mkdir 那一刻就是 0700，因此不再存在“先宽松可见、后收紧”的 TOCTOU 窗口。
    set_mode(path, KEY_DIRECTORY_MODE)
}

/// 创建密钥目录，并保证在 Unix 上首次创建即为 0700。
fn create_restricted_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        // mkdir 直接带上目标权限位，避免进程 umask（常见 0022 会产出世界可读的 0755）
        // 让密钥目录在被收紧之前短暂对外可列。
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(KEY_DIRECTORY_MODE)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        // 非 Unix 平台没有 POSIX mode 概念，权限由 ACL 继承决定，保持原有语义。
        fs::create_dir_all(path)
    }
}

pub(crate) fn secure_existing_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(invalid_storage_path());
    }
    set_mode(path, PRIVATE_FILE_MODE)
}

pub(crate) fn remove_secure_file(path: &Path) -> io::Result<()> {
    secure_existing_file(path)?;
    fs::remove_file(path)?;
    sync_directory(path.parent());
    Ok(())
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
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => secure_existing_file(path)?,
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
    let result = write_temporary(&temporary, path, contents, replace_existing);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// 删除指定命名空间里、由中断的原子写入留下的临时文件。
///
/// 只匹配该命名空间的前缀；目录里的持久化密钥、对方子系统的半成品、以及其它
/// 文件一律不动。删除仍走安全文件检查，符号链接或非常规路径 fail-closed。
pub(crate) fn cleanup_stale_temporary_files(directory: &Path) -> io::Result<()> {
    cleanup_stale_temporary_files_in(directory, TemporaryFileKind::SigningKey)
}

pub(crate) fn cleanup_stale_temporary_files_in(
    directory: &Path,
    kind: TemporaryFileKind,
) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if is_temporary_file(file_name, kind) {
            remove_secure_file(&path)?;
        }
    }
    Ok(())
}

pub(crate) fn modified_time(path: &Path) -> io::Result<std::time::SystemTime> {
    secure_existing_file(path)?;
    fs::metadata(path)?.modified()
}

fn write_temporary(
    temporary: &Path,
    destination: &Path,
    contents: &[u8],
    replace_existing: bool,
) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, PRIVATE_FILE_MODE);
    let mut file = options.open(temporary)?;
    set_file_mode(&file)?;
    file.write_all(contents)?;
    file.sync_all()?;

    if replace_existing {
        fs::rename(temporary, destination)?;
    } else {
        fs::hard_link(temporary, destination)?;
        let _ = fs::remove_file(temporary);
    }
    sync_directory(destination.parent());
    Ok(())
}

fn is_temporary_file(file_name: &str, kind: TemporaryFileKind) -> bool {
    file_name
        .strip_prefix(kind.prefix())
        .and_then(|name| name.strip_suffix(TEMPORARY_FILE_SUFFIX))
        .is_some_and(|unique| !unique.is_empty())
}

fn sync_directory(path: Option<&Path>) {
    #[cfg(unix)]
    if let Some(path) = path
        && let Ok(directory) = File::open(path)
    {
        let _ = directory.sync_all();
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn set_file_mode(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn invalid_storage_path() -> io::Error {
    io::Error::new(ErrorKind::PermissionDenied, "invalid secure storage path")
}

#[cfg(all(test, unix))]
#[path = "key_storage_tests.rs"]
mod tests;
