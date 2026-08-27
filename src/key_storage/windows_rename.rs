//! Windows 密钥文件的原子重命名。
//!
//! `SetFileInformationByHandle(FileRenameInfo)` 只接受 `RootDirectory` 为空的
//! 完整路径形式：父目录句柄相对的变体（RootDirectory 指向目录）在本机
//! Windows 上稳定返回 ERROR_INVALID_PARAMETER。因此调用方必须传入
//! walk() 逐级句柄解析并验证过的同一目录路径（无 \\?\ 前缀），
//! 这里负责拼成内核要求的 `\??\` NT 目标路径。

use std::{ffi::OsStr, fs::File, io, mem, os::windows::ffi::OsStrExt, path::Path, ptr};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_RENAME_INFO, FileRenameInfo, SetFileInformationByHandle,
};

use super::policy::invalid_storage_path;
use super::windows_sys::{map_last_error, raw_handle, validate_basename};

pub(super) fn rename_in_dir(
    file: &File,
    directory_path: &Path,
    new_name: &str,
    replace: bool,
) -> io::Result<()> {
    let nt_path = to_nt_path(directory_path, new_name)?;
    let name_bytes = (nt_path.len() - 1) * 2; // 含结尾 NUL 的缓冲，长度不含它
    let size = mem::size_of::<FILE_RENAME_INFO>() + name_bytes.saturating_sub(2);
    let align = mem::align_of::<FILE_RENAME_INFO>();
    let mut storage = vec![0u8; size + align];
    let offset = storage.as_ptr() as usize % align;
    let aligned = if offset == 0 { 0 } else { align - offset };
    let info = unsafe { storage.as_mut_ptr().add(aligned).cast::<FILE_RENAME_INFO>() };
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = ptr::null_mut();
        (*info).FileNameLength = name_bytes as u32;
        ptr::copy_nonoverlapping(
            nt_path.as_ptr(),
            (*info).FileName.as_mut_ptr(),
            nt_path.len(),
        );
        let ok =
            SetFileInformationByHandle(raw_handle(file), FileRenameInfo, info.cast(), size as u32);
        if ok == 0 {
            return Err(map_last_error());
        }
    }
    Ok(())
}

/// 把已验证的无前缀绝对目录名拼成内核接受的 `\??\` NT 目标路径，
/// 返回以 NUL 结尾的 UTF-16 序列。
fn to_nt_path(directory_path: &Path, new_name: &str) -> io::Result<Vec<u16>> {
    if !directory_path.is_absolute() {
        return Err(invalid_storage_path());
    }
    validate_basename(OsStr::new(new_name))?;
    let mut nt: Vec<u16> = "\\??\\".encode_utf16().collect();
    let mut dir_units: Vec<u16> = directory_path.as_os_str().encode_wide().collect();
    while matches!(dir_units.last(), Some(0x5C)) {
        dir_units.pop();
    }
    nt.extend_from_slice(&dir_units);
    nt.push(0x5C);
    nt.extend(new_name.encode_utf16());
    nt.push(0);
    Ok(nt)
}
