//! Windows 密钥目录的句柄系统调用。
//!
//! 相对打开走 `NtCreateFile` + `FILE_OPEN_REPARSE_POINT`，等价于 Unix 的
//! `openat` + `O_NOFOLLOW`：已持有的目录句柄不会再被路径替换拐走。

use std::{
    ffi::OsStr,
    fs::File,
    io::{self, ErrorKind},
    mem,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, RawHandle},
    },
    path::Path,
    ptr, slice,
};

use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_ID_BOTH_DIR_INFORMATION,
            FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
            FILE_SYNCHRONOUS_IO_NONALERT, FileIdBothDirectoryInformation, NtCreateFile,
            NtQueryDirectoryFile,
        },
    },
    Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, ERROR_DIRECTORY, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
            ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
            INVALID_HANDLE_VALUE, NTSTATUS, RtlNtStatusToDosError, STATUS_FILE_IS_A_DIRECTORY,
            STATUS_NO_MORE_FILES, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
            STATUS_OBJECT_NAME_NOT_FOUND, UNICODE_STRING,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
            FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FileDispositionInfo, FileRenameInfo,
            GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
            SetFileInformationByHandle, WRITE_DAC,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

use super::policy::{FileInode, invalid_storage_path};
use super::windows_acl::ProtectedSd;
use super::windows_policy::{PathKind, reparse_point_rejected};

const OBJ_CASE_INSENSITIVE: u32 = 0x40;

pub(super) fn dir_access() -> u32 {
    FILE_LIST_DIRECTORY
        | FILE_ADD_FILE
        | FILE_ADD_SUBDIRECTORY
        | FILE_TRAVERSE
        | FILE_READ_ATTRIBUTES
        | FILE_DELETE_CHILD
        | READ_CONTROL
        | WRITE_DAC
        | DELETE
        | SYNCHRONIZE
}

pub(super) fn file_read_access() -> u32 {
    GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
}

pub(super) fn file_write_access() -> u32 {
    GENERIC_READ
        | GENERIC_WRITE
        | DELETE
        | WRITE_DAC
        | READ_CONTROL
        | FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
}

pub(super) fn open_dir_path(path: &Path) -> io::Result<File> {
    let wide = path_to_wide(path)?;
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            dir_access(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    file_from_handle(handle)
}

pub(super) fn open_relative(
    parent: &File,
    name: &OsStr,
    access: u32,
    directory: bool,
    create: bool,
    sd: Option<&ProtectedSd>,
) -> io::Result<File> {
    let wide = os_name_to_wide(name)?;
    let mut unicode = UNICODE_STRING {
        Length: (wide.len() * 2) as u16,
        MaximumLength: (wide.len() * 2) as u16,
        Buffer: wide.as_ptr().cast_mut(),
    };
    let mut attrs = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: raw_handle(parent),
        ObjectName: &raw mut unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: sd.map(ProtectedSd::as_ptr).unwrap_or(ptr::null()),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle = ptr::null_mut();
    let mut iosb = unsafe { mem::zeroed::<IO_STATUS_BLOCK>() };
    let options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
    let disposition = if create { FILE_CREATE } else { FILE_OPEN };
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &raw mut attrs,
            &mut iosb,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            options,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(map_ntstatus(status));
    }
    file_from_handle(handle)
}

pub(super) fn rename_in_dir(
    file: &File,
    parent: &File,
    new_name: &str,
    replace: bool,
) -> io::Result<()> {
    validate_basename(OsStr::new(new_name))?;
    let mut wide: Vec<u16> = new_name.encode_utf16().collect();
    wide.push(0);
    let name_bytes = (wide.len() - 1) * 2;
    let extra = name_bytes.saturating_sub(2);
    let size = mem::size_of::<FILE_RENAME_INFO>() + extra;
    let align = mem::align_of::<FILE_RENAME_INFO>();
    let mut storage = vec![0u8; size + align];
    let offset = storage.as_ptr() as usize % align;
    let aligned = if offset == 0 { 0 } else { align - offset };
    let info = unsafe { storage.as_mut_ptr().add(aligned).cast::<FILE_RENAME_INFO>() };
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = raw_handle(parent);
        (*info).FileNameLength = name_bytes as u32;
        ptr::copy_nonoverlapping(wide.as_ptr(), (*info).FileName.as_mut_ptr(), wide.len());
        let ok =
            SetFileInformationByHandle(raw_handle(file), FileRenameInfo, info.cast(), size as u32);
        if ok == 0 {
            return Err(map_last_error());
        }
    }
    Ok(())
}

pub(super) fn dispose_file(file: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    let ok = unsafe {
        SetFileInformationByHandle(
            raw_handle(file),
            FileDispositionInfo,
            (&raw const info).cast(),
            mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        Err(map_last_error())
    } else {
        Ok(())
    }
}

pub(super) fn path_kind(file: &File) -> io::Result<PathKind> {
    let info = handle_info(file)?;
    let attrs = info.dwFileAttributes;
    Ok(PathKind {
        is_dir: attrs & FILE_ATTRIBUTE_DIRECTORY != 0,
        is_reparse: attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        is_regular_file: attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0,
    })
}

pub(super) fn require_kind(file: &File, want_dir: bool) -> io::Result<PathKind> {
    let kind = path_kind(file)?;
    if kind.is_reparse {
        return Err(reparse_point_rejected());
    }
    if want_dir && !kind.is_dir {
        return Err(invalid_storage_path());
    }
    if !want_dir && !kind.is_regular_file {
        return Err(invalid_storage_path());
    }
    Ok(kind)
}

pub(super) fn inode_of(file: &File) -> io::Result<FileInode> {
    let info = handle_info(file)?;
    Ok(FileInode {
        dev: u64::from(info.dwVolumeSerialNumber),
        ino: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

pub(super) struct DirEntry {
    pub name: String,
    pub inode: FileInode,
}

pub(super) fn list_dir(dir: &File) -> io::Result<Vec<DirEntry>> {
    let volume = handle_info(dir)?.dwVolumeSerialNumber;
    let mut buffer = vec![0u8; 16 * 1024];
    let mut entries = Vec::new();
    let mut restart = true;
    loop {
        let mut iosb = unsafe { mem::zeroed::<IO_STATUS_BLOCK>() };
        let status = unsafe {
            NtQueryDirectoryFile(
                raw_handle(dir),
                ptr::null_mut(),
                None,
                ptr::null(),
                &mut iosb,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                FileIdBothDirectoryInformation,
                false,
                ptr::null(),
                restart,
            )
        };
        if status == STATUS_NO_MORE_FILES {
            break;
        }
        if status < 0 {
            return Err(map_ntstatus(status));
        }
        restart = false;
        let mut offset = 0usize;
        loop {
            let info = unsafe {
                &*buffer
                    .as_ptr()
                    .add(offset)
                    .cast::<FILE_ID_BOTH_DIR_INFORMATION>()
            };
            let name_units = (info.FileNameLength / 2) as usize;
            let name = unsafe { slice::from_raw_parts(info.FileName.as_ptr(), name_units) };
            if name != [b'.' as u16] && name != [b'.' as u16, b'.' as u16] {
                if let Ok(name) = String::from_utf16(name) {
                    entries.push(DirEntry {
                        name,
                        inode: FileInode {
                            dev: u64::from(volume),
                            ino: info.FileId as u64,
                        },
                    });
                }
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            offset += info.NextEntryOffset as usize;
        }
    }
    Ok(entries)
}

pub(super) fn raw_handle(file: &File) -> HANDLE {
    file.as_raw_handle() as HANDLE
}

fn handle_info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    let ok = unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) };
    if ok == 0 {
        Err(map_last_error())
    } else {
        Ok(info)
    }
}

fn file_from_handle(handle: HANDLE) -> io::Result<File> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(map_last_error());
    }
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

fn path_to_wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.is_empty() || wide.contains(&0) {
        return Err(invalid_storage_path());
    }
    wide.push(0);
    Ok(wide)
}

fn os_name_to_wide(name: &OsStr) -> io::Result<Vec<u16>> {
    validate_basename(name)?;
    Ok(name.encode_wide().collect())
}

fn validate_basename(name: &OsStr) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(invalid_storage_path());
    }
    let wide: Vec<u16> = name.encode_wide().collect();
    if wide.contains(&0)
        || wide.iter().any(|unit| {
            matches!(
                *unit,
                0x2F | 0x5C | 0x3A | 0x2A | 0x3F | 0x22 | 0x3C | 0x3E | 0x7C
            )
        })
    {
        return Err(invalid_storage_path());
    }
    Ok(())
}

fn map_ntstatus(status: NTSTATUS) -> io::Error {
    if status == STATUS_OBJECT_NAME_NOT_FOUND {
        return io::Error::new(ErrorKind::NotFound, "secure storage path not found");
    }
    if status == STATUS_OBJECT_NAME_COLLISION {
        return io::Error::new(
            ErrorKind::AlreadyExists,
            "secure storage file already exists",
        );
    }
    if status == STATUS_FILE_IS_A_DIRECTORY || status == STATUS_NOT_A_DIRECTORY {
        return invalid_storage_path();
    }
    let dos = unsafe { RtlNtStatusToDosError(status) };
    map_dos(dos)
}

fn map_last_error() -> io::Error {
    map_dos(unsafe { GetLastError() })
}

fn map_dos(code: u32) -> io::Error {
    match code {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => {
            io::Error::new(ErrorKind::NotFound, "secure storage path not found")
        }
        ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS => io::Error::new(
            ErrorKind::AlreadyExists,
            "secure storage file already exists",
        ),
        ERROR_DIRECTORY => invalid_storage_path(),
        _ => io::Error::from_raw_os_error(code as i32),
    }
}

#[cfg(test)]
pub(super) fn create_mount_point_for_test(link: &Path, target: &Path) -> io::Result<()> {
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

    std::fs::create_dir(link)?;
    let handle = unsafe {
        CreateFileW(
            path_to_wide(link)?.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(map_last_error());
    }
    struct Close(HANDLE);
    impl Drop for Close {
        fn drop(&mut self) {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
    let handle = Close(handle);

    let target = std::fs::canonicalize(target)?;
    let mut nt = std::ffi::OsString::from(r"\??\");
    let lossy = target.to_string_lossy();
    let stripped = lossy.strip_prefix(r"\\?\").unwrap_or(lossy.as_ref());
    nt.push(stripped);
    let subst: Vec<u16> = nt.encode_wide().collect();
    let print: Vec<u16> = stripped.encode_utf16().collect();

    let path_bytes = (subst.len() + 1 + print.len() + 1) * 2;
    let data_len = 8 + path_bytes;
    let total = 8 + data_len;
    let mut buf = vec![0u8; total];
    buf[0..4].copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buf[4..6].copy_from_slice(&(data_len as u16).to_le_bytes());
    buf[8..10].copy_from_slice(&0u16.to_le_bytes());
    buf[10..12].copy_from_slice(&((subst.len() * 2) as u16).to_le_bytes());
    buf[12..14].copy_from_slice(&(((subst.len() + 1) * 2) as u16).to_le_bytes());
    buf[14..16].copy_from_slice(&((print.len() * 2) as u16).to_le_bytes());
    let mut pos = 16;
    for unit in subst {
        buf[pos..pos + 2].copy_from_slice(&unit.to_le_bytes());
        pos += 2;
    }
    pos += 2;
    for unit in print {
        buf[pos..pos + 2].copy_from_slice(&unit.to_le_bytes());
        pos += 2;
    }
    let _ = pos;

    let mut returned = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle.0,
            FSCTL_SET_REPARSE_POINT,
            buf.as_ptr().cast(),
            buf.len() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(map_last_error())
    } else {
        Ok(())
    }
}
