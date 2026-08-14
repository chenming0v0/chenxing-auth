//! Unix 密钥路径的 owner / 权限 / inode 策略。
//!
//! 全部是纯函数：异 uid 场景在普通 CI 里没法 `chown`，必须把判定从文件系统
//! 操作里拆出来才能测到拒绝分支。

use std::io::{self, ErrorKind};

/// 进程凭证：有效 uid，不是真实 uid。密钥目录必须属于当前有效用户。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessIdentity {
    pub uid: u32,
}

/// 一次 fstat / 测试夹具看到的路径身份。`mode` 含 sticky/setgid（低 12 位）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PathIdentity {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub is_regular_file: bool,
}

/// 打开前后必须对上的 inode 身份，用来消掉 check-then-open TOCTOU。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileInode {
    pub dev: u64,
    pub ino: u64,
}

/// KEY_DIRECTORY 叶子：必须是本进程的目录，且不含 group/other 权限位。
///
/// 服务以 root 启动、目录却是别人预先建好的，是 Issue #457 的主攻击面。
/// 只强制有效 uid：0700/0600 下主 gid 不是额外安全边界。
pub(crate) fn leaf_directory_owned(path: PathIdentity, process: ProcessIdentity) -> bool {
    !path.is_symlink && path.is_dir && path.uid == process.uid
}

pub(crate) fn leaf_directory_mode_restricted(mode: u32) -> bool {
    mode & 0o077 == 0
}

pub(crate) fn leaf_directory_trusted(path: PathIdentity, process: ProcessIdentity) -> bool {
    leaf_directory_owned(path, process) && leaf_directory_mode_restricted(path.mode)
}

/// 祖先目录：owner 必须是本进程或 root；group/other 可写只允许 root + sticky
///（`/tmp` 那种 1777）。其它 uid 的祖先可以替换子目录，必须拒绝。
pub(crate) fn ancestor_directory_trusted(path: PathIdentity, process: ProcessIdentity) -> bool {
    if path.is_symlink || !path.is_dir {
        return false;
    }
    if path.uid != process.uid && path.uid != 0 {
        return false;
    }
    if path.mode & 0o022 == 0 {
        return true;
    }
    path.uid == 0 && path.mode & 0o1000 != 0
}

/// 密钥文件：普通文件、本进程所有。mode 由打开后的 fchmod 收紧，这里只看 uid。
pub(crate) fn regular_file_owned(path: PathIdentity, process: ProcessIdentity) -> bool {
    !path.is_symlink && path.is_regular_file && path.uid == process.uid
}

pub(crate) fn same_file_inode(expected: FileInode, actual: FileInode) -> bool {
    expected.dev == actual.dev && expected.ino == actual.ino
}

pub(crate) fn require_same_inode(expected: FileInode, actual: FileInode) -> io::Result<()> {
    if same_file_inode(expected, actual) {
        Ok(())
    } else {
        Err(inode_mismatch())
    }
}

pub(crate) fn inode_mismatch() -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        "secure storage inode changed during open",
    )
}

pub(crate) fn invalid_storage_path() -> io::Error {
    io::Error::new(ErrorKind::PermissionDenied, "invalid secure storage path")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELF: ProcessIdentity = ProcessIdentity { uid: 1000 };
    const ROOT: ProcessIdentity = ProcessIdentity { uid: 0 };

    fn dir(uid: u32, gid: u32, mode: u32) -> PathIdentity {
        PathIdentity {
            uid,
            gid,
            mode,
            is_dir: true,
            is_symlink: false,
            is_regular_file: false,
        }
    }

    fn file(uid: u32, gid: u32, mode: u32) -> PathIdentity {
        PathIdentity {
            uid,
            gid,
            mode,
            is_dir: false,
            is_symlink: false,
            is_regular_file: true,
        }
    }

    #[test]
    fn leaf_rejects_foreign_uid_even_when_mode_is_0700() {
        assert!(leaf_directory_trusted(dir(1000, 1000, 0o700), SELF));
        assert!(
            !leaf_directory_trusted(dir(1001, 1000, 0o700), SELF),
            "异 uid 目录必须拒绝，哪怕权限已经是 0700"
        );
        assert!(
            !leaf_directory_trusted(dir(0, 0, 0o700), SELF),
            "root 拥有的叶子对非 root 进程也不是可信密钥目录"
        );
        assert!(
            leaf_directory_trusted(dir(1000, 1001, 0o700), SELF),
            "同 uid 异 gid 可以接受：0700 下 gid 不是额外边界"
        );
    }

    #[test]
    fn leaf_rejects_group_or_other_permission_bits() {
        assert!(!leaf_directory_mode_restricted(0o750));
        assert!(!leaf_directory_mode_restricted(0o705));
        assert!(leaf_directory_mode_restricted(0o700));
        assert!(!leaf_directory_trusted(dir(1000, 1000, 0o755), SELF));
    }

    #[test]
    fn ancestor_accepts_root_or_self_and_rejects_foreign_uid() {
        assert!(ancestor_directory_trusted(dir(0, 0, 0o755), SELF));
        assert!(ancestor_directory_trusted(dir(1000, 1000, 0o755), SELF));
        assert!(
            !ancestor_directory_trusted(dir(1001, 1001, 0o755), SELF),
            "别人拥有的祖先可以替换 KEY_DIRECTORY"
        );
        assert!(ancestor_directory_trusted(dir(0, 0, 0o755), ROOT));
    }

    #[test]
    fn ancestor_rejects_writable_dirs_unless_root_sticky() {
        assert!(!ancestor_directory_trusted(dir(1000, 1000, 0o775), SELF));
        assert!(!ancestor_directory_trusted(dir(0, 0, 0o775), SELF));
        assert!(
            ancestor_directory_trusted(dir(0, 0, 0o1777), SELF),
            "/tmp 这类 root+sticky 祖先可以接受"
        );
        assert!(!ancestor_directory_trusted(dir(1000, 1000, 0o1777), SELF));
    }

    #[test]
    fn regular_file_rejects_foreign_owner_and_non_files() {
        assert!(regular_file_owned(file(1000, 1000, 0o600), SELF));
        assert!(!regular_file_owned(file(0, 0, 0o600), SELF));
        assert!(
            regular_file_owned(file(1000, 1001, 0o600), SELF),
            "同 uid 异 gid 文件可以接受"
        );
        assert!(!regular_file_owned(dir(1000, 1000, 0o700), SELF));
    }

    #[test]
    fn inode_mismatch_is_a_hard_failure() {
        let first = FileInode { dev: 1, ino: 10 };
        let same = FileInode { dev: 1, ino: 10 };
        let swapped = FileInode { dev: 1, ino: 11 };
        assert!(same_file_inode(first, same));
        assert!(!same_file_inode(first, swapped));
        assert_eq!(
            require_same_inode(first, swapped).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        require_same_inode(first, same).expect("matching inode");
    }
}
