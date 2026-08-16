//! Windows 密钥路径的 DACL / 重解析点策略。
//!
//! 全部是纯函数：真实 SID 与句柄操作留在 `windows_acl` / `windows_sys`，
//! 判定本身必须能在 Linux CI 里测到拒绝分支。

#[cfg(windows)]
use std::io::{self, ErrorKind};

/// 一次 DACL 观察里出现的主体。`Foreign` 覆盖 Users / Everyone / 其它帐户。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WellKnownPrincipal {
    CurrentUser,
    LocalSystem,
    Everyone,
    AuthenticatedUsers,
    BuiltinUsers,
    Foreign,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AceKind {
    Allow,
    Deny,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AceView {
    pub kind: AceKind,
    pub principal: WellKnownPrincipal,
}

/// 叶子目录或密钥文件上看到的安全描述符摘要。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DaclView<'a> {
    pub present: bool,
    pub null_dacl: bool,
    pub protected: bool,
    pub aces: &'a [AceView],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PathKind {
    pub is_dir: bool,
    pub is_reparse: bool,
    pub is_regular_file: bool,
}

pub(crate) fn leaf_directory_kind_trusted(kind: PathKind) -> bool {
    kind.is_dir && !kind.is_reparse
}

pub(crate) fn regular_file_kind_trusted(kind: PathKind) -> bool {
    kind.is_regular_file && !kind.is_dir && !kind.is_reparse
}

pub(crate) fn ancestor_kind_trusted(kind: PathKind) -> bool {
    kind.is_dir && !kind.is_reparse
}

/// 允许出现在叶子 DACL 里的授权主体：当前进程/服务帐户，以及 SYSTEM。
pub(crate) fn principal_is_trusted(principal: WellKnownPrincipal) -> bool {
    matches!(
        principal,
        WellKnownPrincipal::CurrentUser | WellKnownPrincipal::LocalSystem
    )
}

/// 叶子 DACL：必须存在、非 NULL、受保护，且每个 Allow ACE 只授给受信主体。
///
/// NULL DACL 等于 Everyone:F。未保护的 DACL 会在父目录改 ACL 后悄悄扩大。
/// 已有宽松/外来 ACE 必须 fail-closed，不能在打开时静默改写。
pub(crate) fn leaf_dacl_trusted(view: DaclView<'_>) -> bool {
    if !view.present || view.null_dacl || !view.protected {
        return false;
    }
    view.aces.iter().all(ace_is_trusted)
}

fn ace_is_trusted(ace: &AceView) -> bool {
    match ace.kind {
        AceKind::Deny => true,
        AceKind::Allow => principal_is_trusted(ace.principal),
        AceKind::Other => false,
    }
}

#[cfg(windows)]
pub(crate) fn invalid_acl() -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        "secure storage ACL is not restricted to the service account",
    )
}

#[cfg(windows)]
pub(crate) fn reparse_point_rejected() -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        "secure storage path is a reparse point",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(principal: WellKnownPrincipal) -> AceView {
        AceView {
            kind: AceKind::Allow,
            principal,
        }
    }

    fn view<'a>(aces: &'a [AceView], protected: bool) -> DaclView<'a> {
        DaclView {
            present: true,
            null_dacl: false,
            protected,
            aces,
        }
    }

    #[test]
    fn leaf_accepts_current_user_and_system_only() {
        let aces = [
            allow(WellKnownPrincipal::CurrentUser),
            allow(WellKnownPrincipal::LocalSystem),
        ];
        assert!(leaf_dacl_trusted(view(&aces, true)));
        assert!(
            leaf_dacl_trusted(view(&[allow(WellKnownPrincipal::LocalSystem)], true)),
            "仅 SYSTEM 也可以：进程本身就是 LocalSystem 时只有一个 SID"
        );
    }

    #[test]
    fn leaf_accepts_deny_aces_from_untrusted_principals() {
        let aces = [AceView {
            kind: AceKind::Deny,
            principal: WellKnownPrincipal::Foreign,
        }];
        assert!(leaf_dacl_trusted(view(&aces, true)));
    }

    #[test]
    fn leaf_rejects_loose_world_or_users_acl() {
        for principal in [
            WellKnownPrincipal::Everyone,
            WellKnownPrincipal::AuthenticatedUsers,
            WellKnownPrincipal::BuiltinUsers,
        ] {
            let aces = [allow(WellKnownPrincipal::CurrentUser), allow(principal)];
            assert!(
                !leaf_dacl_trusted(view(&aces, true)),
                "{principal:?} 是宽松 ACL，必须 fail-closed"
            );
        }
    }

    #[test]
    fn leaf_rejects_foreign_principal() {
        let aces = [
            allow(WellKnownPrincipal::CurrentUser),
            allow(WellKnownPrincipal::Foreign),
        ];
        assert!(!leaf_dacl_trusted(view(&aces, true)));
    }

    #[test]
    fn leaf_rejects_null_unprotected_or_missing_dacl() {
        let aces = [allow(WellKnownPrincipal::CurrentUser)];
        assert!(!leaf_dacl_trusted(DaclView {
            present: true,
            null_dacl: true,
            protected: true,
            aces: &aces,
        }));
        assert!(!leaf_dacl_trusted(DaclView {
            present: false,
            null_dacl: false,
            protected: true,
            aces: &aces,
        }));
        assert!(
            !leaf_dacl_trusted(view(&aces, false)),
            "未保护的 DACL 会继承父目录的 Users/Everyone"
        );
    }

    #[test]
    fn leaf_rejects_unexpected_ace_types() {
        let aces = [AceView {
            kind: AceKind::Other,
            principal: WellKnownPrincipal::CurrentUser,
        }];
        assert!(!leaf_dacl_trusted(view(&aces, true)));
    }

    #[test]
    fn path_kind_rejects_reparse_points() {
        assert!(leaf_directory_kind_trusted(PathKind {
            is_dir: true,
            is_reparse: false,
            is_regular_file: false,
        }));
        assert!(!leaf_directory_kind_trusted(PathKind {
            is_dir: true,
            is_reparse: true,
            is_regular_file: false,
        }));
        assert!(!regular_file_kind_trusted(PathKind {
            is_dir: false,
            is_reparse: true,
            is_regular_file: true,
        }));
        assert!(!ancestor_kind_trusted(PathKind {
            is_dir: true,
            is_reparse: true,
            is_regular_file: false,
        }));
        assert!(!regular_file_kind_trusted(PathKind {
            is_dir: true,
            is_reparse: false,
            is_regular_file: false,
        }));
    }
}
