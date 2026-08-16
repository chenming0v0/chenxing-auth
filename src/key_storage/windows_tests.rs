use super::*;
use std::{fs, io::ErrorKind, path::Path};

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

fn prepare_key_dir(name: &str) -> TempDirGuard {
    let guard = TempDirGuard::new(name);
    ensure_secure_directory(guard.path()).expect("create key directory");
    guard
}

#[test]
fn ensure_creates_and_survives_restart() {
    let guard = TempDirGuard::new("win-restart");
    let nested = guard.path().join("parent").join("keys");
    ensure_secure_directory(&nested).expect("create");
    let file = nested.join("active-rs256.kid");
    atomic_write(&file, b"cx-active", true).expect("write");
    assert_eq!(read_secure_file(&file).expect("read"), b"cx-active");
    assert!(inspect_secure_file(&file).expect("present"));

    ensure_secure_directory(&nested).expect("reopen existing secure directory");
    assert_eq!(
        read_secure_file(&file).expect("read after restart"),
        b"cx-active"
    );
}

#[test]
fn ensure_rejects_existing_loose_acl() {
    let guard = TempDirGuard::new("win-loose");
    fs::create_dir_all(guard.path()).expect("default-acl directory");
    let error = ensure_secure_directory(guard.path()).expect_err("loose ACL must fail closed");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn ensure_rejects_foreign_principal() {
    let guard = prepare_key_dir("win-foreign");
    windows::apply_foreign_acl_for_test(guard.path()).expect("plant Users ACE");
    let error = ensure_secure_directory(guard.path()).expect_err("foreign SID must fail closed");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn read_rejects_directory_replaced_with_reparse() {
    let guard = prepare_key_dir("win-reparse-dir");
    let real = guard.path().join("real");
    fs::create_dir(&real).ok();
    let link = guard.path().join("link");
    windows_sys::create_mount_point_for_test(&link, &real)
        .or_else(|_| std::os::windows::fs::symlink_dir(&real, &link))
        .expect("create junction or directory symlink");

    let error = ensure_secure_directory(&link).expect_err("reparse directory must be rejected");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    let nested = ensure_secure_directory(&link.join("keys"));
    assert_eq!(nested.unwrap_err().kind(), ErrorKind::PermissionDenied);
}

#[test]
fn read_rejects_file_replaced_with_reparse() {
    let guard = prepare_key_dir("win-reparse-file");
    let file = guard.path().join("active-rs256.kid");
    atomic_write(&file, b"cx-original", true).expect("write kid");

    fs::remove_file(&file).expect("remove regular file");
    let decoy = guard.path().join("decoy");
    fs::write(&decoy, b"attacker-key").expect("decoy");
    let planted = std::os::windows::fs::symlink_file(&decoy, &file).or_else(|_| {
        let decoy_dir = guard.path().join("decoy-dir");
        fs::create_dir(&decoy_dir)?;
        windows_sys::create_mount_point_for_test(&file, &decoy_dir)
    });
    planted.expect("plant file symlink or mount point");

    let error = read_secure_file(&file).expect_err("reparse must not be read");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert!(inspect_secure_file(&file).is_err());
}

#[test]
fn atomic_write_refuses_to_replace_through_reparse_name() {
    let guard = prepare_key_dir("win-replace-reparse");
    let dest = guard.path().join("oauth-provider-secret.key");
    let other = guard.path().join("other");
    fs::create_dir(&other).expect("target");
    windows_sys::create_mount_point_for_test(&dest, &other)
        .or_else(|_| std::os::windows::fs::symlink_dir(&other, &dest))
        .expect("plant dest reparse");

    let error = atomic_write(&dest, b"secret-material", true)
        .expect_err("must not follow or overwrite via reparse");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn atomic_write_no_replace_preserves_existing() {
    let guard = prepare_key_dir("win-no-replace");
    let path = guard.path().join("rs256-cx-first.pkcs1.der");
    atomic_write(&path, b"first-key", false).expect("first write");
    let error = atomic_write(&path, b"second-key", false).expect_err("no-replace");
    assert_eq!(error.kind(), ErrorKind::AlreadyExists);
    assert_eq!(read_secure_file(&path).expect("unchanged"), b"first-key");
}

#[test]
fn read_rejects_inode_replaced_between_list_and_open() {
    let guard = prepare_key_dir("win-inode-race");
    let name = "rs256-cx-old.pkcs1.der";
    let path = guard.path().join(name);
    atomic_write(&path, b"first-key", false).expect("write first material");

    let listed = windows::list_for_test(guard.path()).expect("list");
    let original = listed
        .iter()
        .find(|entry| entry.name == name)
        .expect("listed key")
        .inode;

    fs::remove_file(&path).expect("remove");
    atomic_write(&path, b"replacement-key", false).expect("replacement");
    let replacement = windows::inode_of_path(&path).expect("new inode");
    assert_ne!(
        (original.dev, original.ino),
        (replacement.dev, replacement.ino),
        "replacement must be a different file id"
    );

    let error = windows::read_named_for_test(guard.path(), name, original)
        .expect_err("inode mismatch must fail closed");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
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
}

#[test]
fn errors_do_not_embed_file_contents() {
    let guard = prepare_key_dir("win-error-text");
    let path = guard.path().join("active-rs256.kid");
    atomic_write(&path, b"super-secret-key-bytes", true).expect("write");
    windows::apply_loose_acl_for_test(guard.path()).ok();
    let error = read_secure_file(&path)
        .err()
        .or_else(|| ensure_secure_directory(guard.path()).err());
    if let Some(error) = error {
        let text = error.to_string();
        assert!(
            !text.contains("super-secret-key-bytes"),
            "error must not include file contents: {text}"
        );
    }
}
