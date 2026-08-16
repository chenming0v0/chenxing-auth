//! 非 Unix / 非 Windows 目标没有 owner、DACL 或 `O_NOFOLLOW` 等价物。
//! 不假装做路径级检查，安全文件操作一律返回 `Unsupported`。

use std::{
    io::{self, ErrorKind},
    path::Path,
};

use super::SecureDirEntry;

fn unsupported() -> io::Error {
    io::Error::new(
        ErrorKind::Unsupported,
        "secure key storage is only implemented on Unix and Windows",
    )
}

pub(super) fn ensure_secure_directory(_: &Path) -> io::Result<()> {
    Err(unsupported())
}

pub(super) fn remove_secure_file(_: &Path) -> io::Result<()> {
    Err(unsupported())
}

pub(super) fn atomic_write(_: &Path) -> io::Result<()> {
    Err(unsupported())
}

pub(super) fn read_secure_named(_: &Path) -> io::Result<super::SecureFileData> {
    Err(unsupported())
}

pub(super) fn list_secure_names(_: &Path) -> io::Result<Vec<SecureDirEntry>> {
    Err(unsupported())
}

pub(super) fn inspect_secure_file(_: &Path) -> io::Result<bool> {
    Err(unsupported())
}
