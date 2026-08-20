use super::*;
use std::{
    fs,
    io::{self, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use uuid::Uuid;

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

fn mode_of(path: &Path) -> io::Result<u32> {
    Ok(fs::symlink_metadata(path)?.permissions().mode() & 0o777)
}

fn prepare_key_dir(name: &str) -> TempDirGuard {
    let guard = TempDirGuard::new(name);
    ensure_secure_directory(guard.path()).expect("create key directory");
    guard
}

#[test]
fn test_ensure_secure_directory_creates_with_0700() {
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
    let guard = TempDirGuard::new("existing-loose");
    fs::create_dir_all(guard.path()).expect("create with default umask");
    fs::set_permissions(guard.path(), fs::Permissions::from_mode(0o755))
        .expect("set loose permissions");

    assert_eq!(mode_of(guard.path()).expect("initial mode"), 0o755);

    ensure_secure_directory(guard.path()).expect("should tighten existing directory");

    assert_eq!(mode_of(guard.path()).expect("tightened mode"), 0o700);
}

#[test]
fn test_ensure_secure_directory_rejects_symlink_to_dir() {
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
fn test_ensure_secure_directory_rejects_symlink_ancestor() {
    use std::os::unix::fs::symlink;

    let guard = TempDirGuard::new("symlink-ancestor");
    fs::create_dir_all(guard.path()).expect("create base directory");

    let real_dir = guard.path().join("real");
    fs::create_dir(&real_dir).expect("create real directory");
    let link = guard.path().join("link");
    symlink(&real_dir, &link).expect("create ancestor symlink");

    let result = ensure_secure_directory(&link.join("keys"));
    assert_eq!(result.unwrap_err().kind(), ErrorKind::PermissionDenied);
}

#[test]
fn read_rejects_file_replaced_with_symlink() {
    use std::os::unix::fs::symlink;

    let guard = prepare_key_dir("symlink-replace");
    let file = guard.path().join("active-rs256.kid");
    atomic_write(&file, b"cx-original", true).expect("write kid");

    fs::remove_file(&file).expect("remove regular file");
    let decoy = guard.path().join("decoy");
    fs::write(&decoy, b"attacker-key").expect("decoy");
    symlink(&decoy, &file).expect("plant symlink");

    let error = read_secure_file(&file).expect_err("symlink must not be read");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert!(inspect_secure_file(&file).is_err());
}

#[test]
fn read_rejects_inode_replaced_between_list_and_open() {
    let guard = prepare_key_dir("inode-race");
    let name = "rs256-cx-old.pkcs1.der";
    let path = guard.path().join(name);
    atomic_write(&path, b"first-key", false).expect("write first material");

    let listed = unix::list_for_test(guard.path()).expect("list");
    let original = listed
        .iter()
        .find(|entry| entry.name == name)
        .expect("listed key")
        .inode;

    let replacement_path = guard.path().join("replacement-material");
    fs::write(&replacement_path, b"replacement-key").expect("plant replacement");
    fs::rename(&replacement_path, &path).expect("swap replacement into place");
    let replacement = unix::inode_of_path(&path).expect("new inode");
    assert_ne!(
        (original.dev, original.ino),
        (replacement.dev, replacement.ino),
        "replacement must be a different inode"
    );

    let error = unix::read_named_for_test(guard.path(), name, original)
        .expect_err("inode mismatch must fail closed");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn read_tightens_loose_mode_via_dirfd() {
    let guard = prepare_key_dir("tighten-file");
    let path = guard.path().join("active-rs256.kid");
    atomic_write(&path, b"kid", true).expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");
    assert_eq!(mode_of(&path).expect("loose mode"), 0o644);
    assert_eq!(read_secure_file(&path).expect("read"), b"kid");
    assert_eq!(mode_of(&path).expect("file mode"), 0o600);
}

#[test]
fn atomic_write_and_read_round_trip_through_dirfd() {
    let guard = prepare_key_dir("round-trip");
    let path = guard.path().join("active-rs256.kid");
    atomic_write(&path, b"cx-active", true).expect("write");
    assert_eq!(read_secure_file(&path).expect("read"), b"cx-active");
    assert_eq!(mode_of(&path).expect("file mode"), 0o600);
    assert!(inspect_secure_file(&path).expect("present"));
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
    let guard = prepare_key_dir("tmp-ns");
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

fn dir_with_two_keys(name: &str) -> TempDirGuard {
    let guard = prepare_key_dir(name);
    fs::write(guard.path().join("rs256-a.pkcs1.der"), b"a").expect("key a");
    fs::write(guard.path().join("rs256-b.pkcs1.der"), b"b").expect("key b");
    guard
}

fn listed_names(directory: &Path) -> io::Result<Vec<String>> {
    let mut names = list_secure_names(directory)?
        .into_iter()
        .map(|entry| entry.name)
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

fn assert_complete_two_key_inventory(names: Vec<String>) {
    assert_eq!(
        names,
        vec![
            "rs256-a.pkcs1.der".to_string(),
            "rs256-b.pkcs1.der".to_string()
        ]
    );
}

#[test]
fn list_dir_fails_closed_on_mid_enumeration_readdir_errors() {
    for errno in [libc::EIO, libc::ENOMEM, libc::EBADF] {
        let guard = dir_with_two_keys("readdir-partial");
        // 3 次成功之后通常已读完 `.`/`..` 和第一个密钥；下一次失败不得返回前缀。
        let _fault = super::unix_sys::readdir_test::fail_after(3, errno);
        let error = list_secure_names(guard.path())
            .expect_err("readdir failure must not return a partial inventory");
        assert_eq!(error.raw_os_error(), Some(errno), "errno {errno}");
    }
}

#[test]
fn list_dir_retries_eintr_and_returns_complete_inventory() {
    let guard = dir_with_two_keys("readdir-eintr");
    let _fault = super::unix_sys::readdir_test::fail_after(3, libc::EINTR);
    let names = listed_names(guard.path()).expect("EINTR must be retried");
    assert_complete_two_key_inventory(names);
}

#[test]
fn list_dir_treats_null_with_cleared_errno_as_eof() {
    let guard = dir_with_two_keys("readdir-eof");
    let _stale = super::unix_sys::readdir_test::stale_errno(libc::EIO);
    let names = listed_names(guard.path()).expect("stale errno must not turn EOF into an error");
    assert_complete_two_key_inventory(names);
}

#[test]
fn cleanup_fails_closed_when_readdir_errors() {
    let guard = dir_with_two_keys("readdir-cleanup");
    let _fault = super::unix_sys::readdir_test::fail_after(3, libc::EIO);
    cleanup_stale_temporary_files(guard.path())
        .expect_err("inventory error must fail closed on cleanup");
}
