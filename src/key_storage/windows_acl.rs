//! Windows 密钥对象的受信 Owner 与受保护 DACL。
//!
//! 叶子只允许当前进程 SID / SYSTEM 持有并取得完整控制权。已有对象只校验、不改写。

#[cfg(test)]
use std::mem;
use std::{io, ptr};

#[cfg(test)]
use windows_sys::Win32::Foundation::GENERIC_ALL;
#[cfg(test)]
use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
#[cfg(test)]
use windows_sys::Win32::Security::{
    ACL_REVISION, AddAccessAllowedAceEx, InitializeAcl, PROTECTED_DACL_SECURITY_INFORMATION,
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, LocalFree},
    Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
    Security::{
        ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACE_HEADER, ACL, CopySid, CreateWellKnownSid,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetTokenInformation, IsValidSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_DESCRIPTOR_CONTROL,
        SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinAuthenticatedUserSid,
        WinBuiltinUsersSid, WinLocalSystemSid, WinWorldSid,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

use super::policy::invalid_storage_path;
use super::windows_policy::{
    AceKind, AceView, DaclView, WellKnownPrincipal, invalid_acl, leaf_dacl_trusted,
};

/// `ACE_HEADER` 类型宽度 ABI 稳定；类型常量取自 ntsecapi 惯例。
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

pub(super) struct SidBuf {
    bytes: Vec<u8>,
}

impl SidBuf {
    fn from_psid(sid: PSID) -> io::Result<Self> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(invalid_storage_path());
        }
        let len = unsafe { GetLengthSid(sid) };
        let mut bytes = vec![0u8; len as usize];
        let copied = unsafe { CopySid(len, bytes.as_mut_ptr().cast(), sid) };
        if copied == 0 {
            return Err(io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32
            ));
        }
        Ok(Self { bytes })
    }

    fn well_known(kind: i32) -> io::Result<Self> {
        let mut size = SECURITY_MAX_SID_SIZE;
        let mut bytes = vec![0u8; size as usize];
        let ok = unsafe {
            CreateWellKnownSid(kind, ptr::null_mut(), bytes.as_mut_ptr().cast(), &mut size)
        };
        if ok == 0 {
            return Err(io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32
            ));
        }
        bytes.truncate(size as usize);
        Ok(Self { bytes })
    }

    pub(super) fn as_psid(&self) -> PSID {
        self.bytes.as_ptr().cast_mut().cast()
    }

    fn eq_sid(&self, other: PSID) -> bool {
        !other.is_null() && unsafe { EqualSid(self.as_psid(), other) } != 0
    }
}

pub(super) struct TrustedSids {
    current: SidBuf,
    system: SidBuf,
    everyone: SidBuf,
    authenticated: SidBuf,
    users: SidBuf,
}

impl TrustedSids {
    pub(super) fn load() -> io::Result<Self> {
        Ok(Self {
            current: current_user_sid()?,
            system: SidBuf::well_known(WinLocalSystemSid)?,
            everyone: SidBuf::well_known(WinWorldSid)?,
            authenticated: SidBuf::well_known(WinAuthenticatedUserSid)?,
            users: SidBuf::well_known(WinBuiltinUsersSid)?,
        })
    }

    fn classify(&self, sid: PSID) -> WellKnownPrincipal {
        if self.current.eq_sid(sid) {
            WellKnownPrincipal::CurrentUser
        } else if self.system.eq_sid(sid) {
            WellKnownPrincipal::LocalSystem
        } else if self.everyone.eq_sid(sid) {
            WellKnownPrincipal::Everyone
        } else if self.authenticated.eq_sid(sid) {
            WellKnownPrincipal::AuthenticatedUsers
        } else if self.users.eq_sid(sid) {
            WellKnownPrincipal::BuiltinUsers
        } else {
            WellKnownPrincipal::Foreign
        }
    }

    pub(super) fn grant_sids(&self) -> impl Iterator<Item = &SidBuf> {
        let same = self.current.eq_sid(self.system.as_psid());
        std::iter::once(&self.current).chain((!same).then_some(&self.system))
    }
}

pub(super) fn validate_leaf_security(handle: HANDLE, sids: &TrustedSids) -> io::Result<()> {
    let snapshot = read_dacl(handle, sids)?;
    if leaf_dacl_trusted(snapshot.view()) {
        Ok(())
    } else {
        Err(invalid_acl())
    }
}

struct DaclSnapshot {
    _sd: LocalSd,
    owner: WellKnownPrincipal,
    present: bool,
    null_dacl: bool,
    protected: bool,
    aces: Vec<AceView>,
}

impl DaclSnapshot {
    fn view(&self) -> DaclView<'_> {
        DaclView {
            owner: self.owner,
            present: self.present,
            null_dacl: self.null_dacl,
            protected: self.protected,
            aces: &self.aces,
        }
    }
}

struct LocalSd(PSECURITY_DESCRIPTOR);

impl Drop for LocalSd {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

fn read_dacl(handle: HANDLE, sids: &TrustedSids) -> io::Result<DaclSnapshot> {
    let mut owner = ptr::null_mut();
    let mut group = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut sacl = ptr::null_mut();
    let mut sd = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut sd,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let sd = LocalSd(sd);
    let owner = sids.classify(owner);
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl_ptr = ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl_ptr, &mut defaulted) } == 0
    {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    let mut control: SECURITY_DESCRIPTOR_CONTROL = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(sd.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    let present = present != 0;
    let null_dacl = present && dacl_ptr.is_null();
    let protected = control & SE_DACL_PROTECTED != 0;
    let aces = if present && !dacl_ptr.is_null() {
        collect_aces(dacl_ptr, sids)?
    } else {
        Vec::new()
    };
    Ok(DaclSnapshot {
        _sd: sd,
        owner,
        present,
        null_dacl,
        protected,
        aces,
    })
}

fn collect_aces(acl: *const ACL, sids: &TrustedSids) -> io::Result<Vec<AceView>> {
    let count = unsafe { (*acl).AceCount } as usize;
    let mut aces = Vec::with_capacity(count);
    for index in 0..count {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 {
            return Err(io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32
            ));
        }
        let header = ace.cast::<ACE_HEADER>();
        let kind = match unsafe { (*header).AceType } {
            ACCESS_ALLOWED_ACE_TYPE => AceKind::Allow,
            ACCESS_DENIED_ACE_TYPE => AceKind::Deny,
            _ => AceKind::Other,
        };
        let (principal, mask) = match kind {
            AceKind::Allow => {
                let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
                let sid = unsafe { ptr::addr_of!((*allowed).SidStart) as PSID };
                (sids.classify(sid), unsafe { (*allowed).Mask })
            }
            AceKind::Deny => {
                let denied = ace.cast::<ACCESS_DENIED_ACE>();
                let sid = unsafe { ptr::addr_of!((*denied).SidStart) as PSID };
                (sids.classify(sid), unsafe { (*denied).Mask })
            }
            AceKind::Other => (WellKnownPrincipal::Foreign, 0),
        };
        aces.push(AceView {
            kind,
            principal,
            mask,
        });
    }
    Ok(aces)
}

fn current_user_sid() -> io::Result<SidBuf> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }
    let token = TokenHandle(token);
    let mut needed = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
    let mut buffer = vec![0u8; needed as usize];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    SidBuf::from_psid(user.User.Sid)
}

#[cfg(test)]
pub(super) fn apply_allow_everyone_for_test(handle: HANDLE) -> io::Result<()> {
    let everyone = SidBuf::well_known(WinWorldSid)?;
    let acl_size = mem::size_of::<ACL>()
        + mem::size_of::<ACCESS_ALLOWED_ACE>()
        + SECURITY_MAX_SID_SIZE as usize;
    let mut acl = vec![0u8; acl_size];
    if unsafe { InitializeAcl(acl.as_mut_ptr().cast(), acl_size as u32, ACL_REVISION) } == 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    if unsafe {
        AddAccessAllowedAceEx(
            acl.as_mut_ptr().cast(),
            ACL_REVISION,
            0,
            GENERIC_ALL,
            everyone.as_psid(),
        )
    } == 0
    {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl.as_ptr().cast(),
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn apply_foreign_principal_for_test(handle: HANDLE) -> io::Result<()> {
    let sids = TrustedSids::load()?;
    let users = SidBuf::well_known(WinBuiltinUsersSid)?;
    let grant: Vec<&SidBuf> = sids.grant_sids().chain(std::iter::once(&users)).collect();
    let acl_size = mem::size_of::<ACL>()
        + grant.len() * (mem::size_of::<ACCESS_ALLOWED_ACE>() + SECURITY_MAX_SID_SIZE as usize);
    let mut acl = vec![0u8; acl_size];
    if unsafe { InitializeAcl(acl.as_mut_ptr().cast(), acl_size as u32, ACL_REVISION) } == 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    for sid in grant {
        if unsafe {
            AddAccessAllowedAceEx(
                acl.as_mut_ptr().cast(),
                ACL_REVISION,
                0,
                GENERIC_ALL,
                sid.as_psid(),
            )
        } == 0
        {
            return Err(io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32
            ));
        }
    }
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl.as_ptr().cast(),
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}
