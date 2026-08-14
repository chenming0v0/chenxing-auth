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

#[test]
fn temporary_file_namespaces_do_not_overlap() {
    assert!(is_temporary_file(
        ".chenxing-key-deadbeef.tmp",
        TemporaryFileKind::SigningKey
    ));
    assert!(!is_temporary_file(
        ".chenxing-key-deadbeef.tmp",
        TemporaryFileKind::ProviderSecret
    ));
    assert!(is_temporary_file(
        ".chenxing-secret-deadbeef.tmp",
        TemporaryFileKind::ProviderSecret
    ));
    assert!(!is_temporary_file(
        ".chenxing-secret-deadbeef.tmp",
        TemporaryFileKind::SigningKey
    ));
    assert!(!is_temporary_file(
        ".chenxing-key-.tmp",
        TemporaryFileKind::SigningKey
    ));
    assert!(!is_temporary_file(
        "rs256-foo.pkcs1.der",
        TemporaryFileKind::SigningKey
    ));
}

#[test]
fn cleanup_only_removes_temporaries_from_the_requested_namespace() {
    let guard = TempDirGuard::new("tmp-ns");
    ensure_secure_directory(guard.path()).expect("secure directory");
    let key_tmp = guard.path().join(".chenxing-key-aaaa.tmp");
    let secret_tmp = guard.path().join(".chenxing-secret-bbbb.tmp");
    let persisted = guard.path().join("oauth-provider-secret.key");
    fs::write(&key_tmp, b"key-temp").expect("key temp");
    fs::write(&secret_tmp, b"secret-temp").expect("secret temp");
    fs::write(&persisted, b"persisted").expect("persisted file");

    cleanup_stale_temporary_files_in(guard.path(), TemporaryFileKind::SigningKey)
        .expect("key cleanup");
    assert!(!key_tmp.exists(), "key namespace temp must be removed");
    assert!(
        secret_tmp.exists(),
        "secret namespace temp must survive key cleanup"
    );
    assert!(persisted.exists(), "persisted files must survive cleanup");

    cleanup_stale_temporary_files_in(guard.path(), TemporaryFileKind::ProviderSecret)
        .expect("secret cleanup");
    assert!(
        !secret_tmp.exists(),
        "secret namespace temp must be removed"
    );
    assert!(
        persisted.exists(),
        "persisted files must survive secret cleanup"
    );
}
