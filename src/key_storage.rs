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

pub(crate) fn atomic_write(path: &Path, contents: &[u8], replace_existing: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => secure_existing_file(path)?,
        Ok(_) => return Err(invalid_storage_path()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let parent = path.parent().ok_or_else(invalid_storage_path)?;
    let temporary = parent.join(format!(".chenxing-key-{}.tmp", Uuid::new_v4().simple()));
    let result = write_temporary(&temporary, path, contents, replace_existing);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
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
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// 测试临时目录的 RAII 清理卫士
    struct TempDirGuard(std::path::PathBuf);

    impl TempDirGuard {
        fn new(name: &str) -> Self {
            let unique = Uuid::new_v4().simple();
            let path = std::env::temp_dir().join(format!("chenxing-test-{name}-{unique}"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// 读取目录实际权限位（低9位）
    fn mode_of(path: &Path) -> io::Result<u32> {
        Ok(fs::symlink_metadata(path)?.permissions().mode() & 0o777)
    }

    #[test]
    fn test_ensure_secure_directory_creates_with_0700() {
        // 验证新建目录从创建那一刻就是 0700，中间目录也应如此。
        let guard = TempDirGuard::new("new-nested");
        let nested = guard.path().join("parent").join("child");

        ensure_secure_directory(&nested).expect("should create nested directory");

        assert_eq!(
            mode_of(&guard.path().join("parent")).expect("parent mode"),
            0o700,
            "中间目录应为 0700"
        );
        assert_eq!(
            mode_of(&nested).expect("leaf mode"),
            0o700,
            "叶子目录应为 0700"
        );
    }

    #[test]
    fn test_ensure_secure_directory_tightens_existing_loose_dir() {
        // 验证已存在的、权限宽松的目录会被收紧到 0700。
        let guard = TempDirGuard::new("existing-loose");
        fs::create_dir_all(guard.path()).expect("create with default umask");
        fs::set_permissions(guard.path(), fs::Permissions::from_mode(0o755))
            .expect("set loose permissions");

        assert_eq!(
            mode_of(guard.path()).expect("initial mode"),
            0o755,
            "初始应为宽松权限"
        );

        ensure_secure_directory(guard.path()).expect("should tighten existing directory");

        assert_eq!(
            mode_of(guard.path()).expect("tightened mode"),
            0o700,
            "应被收紧到 0700"
        );
    }

    #[test]
    fn test_ensure_secure_directory_rejects_symlink_to_dir() {
        // 验证符号链接（即使指向合法目录）会被拒绝，防止私钥落入攻击者可控路径。
        use std::os::unix::fs::symlink;

        let guard = TempDirGuard::new("symlink-target");
        fs::create_dir_all(guard.path()).expect("create base directory");

        let real_dir = guard.path().join("real");
        fs::create_dir(&real_dir).expect("create real directory");

        let symlink_path = guard.path().join("link");
        symlink(&real_dir, &symlink_path).expect("create symlink to directory");

        let result = ensure_secure_directory(&symlink_path);
        assert!(result.is_err(), "应拒绝符号链接");
        assert_eq!(result.unwrap_err().kind(), ErrorKind::PermissionDenied);
    }
}
