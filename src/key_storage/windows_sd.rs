//! Windows 密钥对象的创建期安全描述符与受保护 DACL 写入。
//!
//! 校验入口（`validate_leaf_security` 等）仍在 [`super::windows_acl`]；
//! 这里只负责“我们亲手创建对象”一侧：构造只允许当前进程 SID 与
//! SYSTEM 的受保护 DACL，并按内核要求的格式交付。

use std::{ffi::c_void, io, mem, ptr};

use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, GENERIC_ALL, GetLastError, HANDLE},
    Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo},
    Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, InitializeAcl, InitializeSecurityDescriptor, MakeSelfRelativeSD,
        OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl,
    },
};

use super::policy::invalid_storage_path;
use super::windows_acl::TrustedSids;

/// 创建对象时附带的安全描述符。`sd` 保持绝对格式以便直接取出 Dacl 指针
/// 交给 `SetSecurityInfo`；`relative` 是同一描述符的自相对副本——内核的
/// `NtCreateFile` 只接受 `SE_SELF_RELATIVE` 格式，传绝对格式会得到
/// STATUS_INVALID_PARAMETER（DOS 错误 87）。
pub(super) struct ProtectedSd {
    sd: SECURITY_DESCRIPTOR,
    _acl: Vec<u8>,
    _relative: Vec<u8>,
}

impl ProtectedSd {
    pub(super) fn for_directory(sids: &TrustedSids) -> io::Result<Self> {
        build_sd(sids, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE)
    }

    pub(super) fn for_file(sids: &TrustedSids) -> io::Result<Self> {
        build_sd(sids, 0)
    }

    pub(super) fn as_ptr(&self) -> *const SECURITY_DESCRIPTOR {
        self._relative.as_ptr().cast()
    }
}

fn build_sd(sids: &TrustedSids, inherit: u32) -> io::Result<ProtectedSd> {
    let grant: Vec<&_> = sids.grant_sids().collect();
    let acl_size = mem::size_of::<ACL>()
        + grant.len() * (mem::size_of::<ACCESS_ALLOWED_ACE>() + SECURITY_MAX_SID_SIZE as usize);
    let mut acl = vec![0u8; acl_size];
    if unsafe { InitializeAcl(acl.as_mut_ptr().cast(), acl_size as u32, ACL_REVISION) } == 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    for sid in grant {
        let ok = unsafe {
            AddAccessAllowedAceEx(
                acl.as_mut_ptr().cast(),
                ACL_REVISION,
                inherit,
                GENERIC_ALL,
                sid.as_psid(),
            )
        };
        if ok == 0 {
            return Err(io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32
            ));
        }
    }

    let mut sd = unsafe { mem::zeroed::<SECURITY_DESCRIPTOR>() };
    if unsafe { InitializeSecurityDescriptor((&raw mut sd).cast(), SD_REVISION) } == 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    if unsafe { SetSecurityDescriptorDacl((&raw mut sd).cast(), 1, acl.as_ptr().cast(), 0) } == 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    if unsafe {
        SetSecurityDescriptorControl((&raw mut sd).cast(), SE_DACL_PROTECTED, SE_DACL_PROTECTED)
    } == 0
    {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }

    // NtCreateFile 只接受自相对安全描述符；按 Win32 惯例先用空缓冲探大小。
    let mut needed = 0u32;
    let probe_ok = unsafe {
        MakeSelfRelativeSD(
            (&raw mut sd).cast::<c_void>(),
            ptr::null_mut(),
            &raw mut needed,
        )
    };
    if probe_ok != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(invalid_storage_path());
    }
    let mut relative = vec![0u8; needed as usize];
    if unsafe {
        MakeSelfRelativeSD(
            (&raw mut sd).cast::<c_void>(),
            relative.as_mut_ptr().cast(),
            &raw mut needed,
        )
    } == 0
    {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }

    Ok(ProtectedSd {
        sd,
        _acl: acl,
        _relative: relative,
    })
}

/// 对句柄指向的对象整体替换为受保护 DACL（不继承父级 ACE）。
pub(super) fn apply_protected_dacl(
    handle: HANDLE,
    sids: &TrustedSids,
    directory: bool,
) -> io::Result<()> {
    let sd = if directory {
        ProtectedSd::for_directory(sids)?
    } else {
        ProtectedSd::for_file(sids)?
    };
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            sd.sd.Dacl,
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// `SECURITY_DESCRIPTOR_REVISION` 不走 SystemServices feature，值是稳定 ABI。
const SD_REVISION: u32 = 1;
