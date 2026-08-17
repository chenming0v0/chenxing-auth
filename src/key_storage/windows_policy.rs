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
    pub mask: u32,
}

/// 叶子目录或密钥文件上看到的安全描述符摘要。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DaclView<'a> {
    pub owner: WellKnownPrincipal,
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

const GENERIC_ALL_MASK: u32 = 0x1000_0000;
const FILE_ALL_ACCESS_MASK: u32 = 0x001f_01ff;

/// 叶子安全描述符：Owner 必须受信；DACL 必须存在、非 NULL、受保护，且每个
/// Allow ACE 只把完整控制权授给受信主体。
///
/// NULL DACL 等于 Everyone:F。未保护的 DACL 会在父目录改 ACL 后悄悄扩大。
/// 外来 Owner 即使暂时留下受限 DACL，仍能重新放宽权限；两者都必须 fail-closed。
pub(crate) fn leaf_dacl_trusted(view: DaclView<'_>) -> bool {
    if !principal_is_trusted(view.owner) || !view.present || view.null_dacl || !view.protected {
        return false;
    }
    view.aces.iter().all(ace_is_trusted)
}

fn ace_is_trusted(ace: &AceView) -> bool {
    match ace.kind {
        AceKind::Deny => true,
        AceKind::Allow => {
            principal_is_trusted(ace.principal) && allow_mask_grants_full_control(ace.mask)
        }
        AceKind::Other => false,
    }
}

fn allow_mask_grants_full_control(mask: u32) -> bool {
    mask & GENERIC_ALL_MASK != 0 || mask & FILE_ALL_ACCESS_MASK == FILE_ALL_ACCESS_MASK
}

#[cfg(windows)]
pub(crate) fn invalid_acl() -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        "secure storage owner or ACL is not restricted to the service account",
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
            mask: GENERIC_ALL_MASK,
        }
    }

    fn view<'a>(aces: &'a [AceView], protected: bool) -> DaclView<'a> {
        DaclView {
            owner: WellKnownPrincipal::CurrentUser,
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
            mask: GENERIC_ALL_MASK,
        }];
        assert!(leaf_dacl_trusted(view(&aces, true)));
    }

    #[test]
    fn leaf_rejects_an_untrusted_owner_even_when_the_dacl_is_restricted() {
        let aces = [
            allow(WellKnownPrincipal::CurrentUser),
            allow(WellKnownPrincipal::LocalSystem),
        ];
        let mut descriptor = view(&aces, true);
        descriptor.owner = WellKnownPrincipal::Foreign;

        assert!(
            !leaf_dacl_trusted(descriptor),
            "外来 owner 可重写 DACL，不能仅凭当前 ACL 看似受限就信任对象"
        );
    }

    #[test]
    fn leaf_requires_full_control_masks_for_trusted_allow_aces() {
        let read_only = [AceView {
            kind: AceKind::Allow,
            principal: WellKnownPrincipal::CurrentUser,
            mask: 0x8000_0000,
        }];
        assert!(
            !leaf_dacl_trusted(view(&read_only, true)),
            "只校验 SID、不校验 mask 会接受非规范 ACL"
        );

        let expanded_full_control = [AceView {
            kind: AceKind::Allow,
            principal: WellKnownPrincipal::CurrentUser,
            mask: FILE_ALL_ACCESS_MASK,
        }];
        assert!(
            leaf_dacl_trusted(view(&expanded_full_control, true)),
            "Windows 可把 GENERIC_ALL 映射成 FILE_ALL_ACCESS"
        );
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
            owner: WellKnownPrincipal::CurrentUser,
            present: true,
            null_dacl: true,
            protected: true,
            aces: &aces,
        }));
        assert!(!leaf_dacl_trusted(DaclView {
            owner: WellKnownPrincipal::CurrentUser,
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
            mask: GENERIC_ALL_MASK,
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
