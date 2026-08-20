//! Unix 密钥目录：沿路径用 dirfd + openat/openat2 前进，打开后 fstat。
//!
//! 路径级 lstat 再 open 有 TOCTOU。这里每一步都绑定已验证的目录 fd，
//! 最终分量带 O_NOFOLLOW。绝对路径走查用 openat2(NO_SYMLINKS|NO_MAGICLINKS)，
//! 已验证目录内的单分量才加 RESOLVE_BENEATH。

use std::{
    ffi::{CStr, OsStr, OsString},
    fs::File,
    io::{self, ErrorKind, Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

use super::policy::{
    FileInode, PathIdentity, ProcessIdentity, ancestor_directory_trusted, invalid_storage_path,
    leaf_directory_owned, leaf_directory_trusted, regular_file_owned, require_same_inode,
};
use super::unix_sys::{
    fchmod, linkat, map_open_error, mkdirat, open_beneath, open_path_component, readdir, renameat,
    unlinkat,
};
use super::{
    KEY_DIRECTORY_MODE, PRIVATE_FILE_MODE, SecureFileData, TEMPORARY_FILE_SUFFIX, TemporaryFileKind,
};

pub(crate) struct SecureDir {
    file: File,
}

#[derive(Debug)]
pub(crate) struct SecureDirEntry {
    pub name: String,
    pub inode: FileInode,
}

pub(crate) fn current_process_identity() -> ProcessIdentity {
    ProcessIdentity {
        // SAFETY: geteuid 无前置条件。owner 只看有效 uid；0700/0600 下 gid 不是边界。
        uid: unsafe { libc::geteuid() },
    }
}

impl SecureDir {
    pub(crate) fn ensure(path: &Path) -> io::Result<Self> {
        walk(path, true)
    }

    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        walk(path, false)
    }

    pub(crate) fn list(&self) -> io::Result<Vec<SecureDirEntry>> {
        list_dir(&self.file)
    }

    pub(crate) fn read_named_limited(
        &self,
        name: &str,
        expected: Option<FileInode>,
        max_bytes: Option<u64>,
    ) -> io::Result<SecureFileData> {
        let file = self.open_regular(name, libc::O_RDONLY, expected)?;
        fchmod(&file, PRIVATE_FILE_MODE)?;
        let modified = file.metadata()?.modified()?;
        let mut contents = Vec::new();
        let mut file = file;
        match max_bytes {
            Some(limit) => {
                file.take(limit.saturating_add(1))
                    .read_to_end(&mut contents)?;
            }
            None => {
                file.read_to_end(&mut contents)?;
            }
        }
        Ok(SecureFileData { contents, modified })
    }

    pub(crate) fn inspect_regular_file(&self, name: &str) -> io::Result<bool> {
        match self.open_regular(name, libc::O_RDONLY, None) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn remove_regular_file(&self, name: &str) -> io::Result<()> {
        let file = self.open_regular(name, libc::O_RDONLY, None)?;
        drop(file);
        unlinkat(self.fd(), name)?;
        self.file.sync_all()
    }

    pub(crate) fn atomic_write(
        &self,
        kind: TemporaryFileKind,
        name: &str,
        contents: &[u8],
        replace_existing: bool,
    ) -> io::Result<()> {
        match self.open_regular(name, libc::O_RDONLY, None) {
            Ok(existing) => {
                fchmod(&existing, PRIVATE_FILE_MODE)?;
                if !replace_existing {
                    return Err(io::Error::new(
                        ErrorKind::AlreadyExists,
                        "secure storage file already exists",
                    ));
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let temporary = format!(
            "{}{}{TEMPORARY_FILE_SUFFIX}",
            kind.prefix(),
            uuid::Uuid::new_v4().simple()
        );
        let result = self.write_temporary(&temporary, name, contents, replace_existing);
        if result.is_err() {
            let _ = unlinkat(self.fd(), &temporary);
        }
        result
    }

    pub(crate) fn open_or_create(&self, name: &str) -> io::Result<File> {
        match self.open_regular(name, libc::O_RDWR, None) {
            Ok(file) => {
                fchmod(&file, PRIVATE_FILE_MODE)?;
                Ok(file)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                match self.create_exclusive(name) {
                    Ok(file) => Ok(file),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                        let file = self.open_regular(name, libc::O_RDWR, None)?;
                        fchmod(&file, PRIVATE_FILE_MODE)?;
                        Ok(file)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    fn write_temporary(
        &self,
        temporary: &str,
        destination: &str,
        contents: &[u8],
        replace_existing: bool,
    ) -> io::Result<()> {
        let mut file = self.create_exclusive(temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        if replace_existing {
            renameat(self.fd(), temporary, destination)?;
        } else {
            linkat(self.fd(), temporary, destination)?;
            let _ = unlinkat(self.fd(), temporary);
        }
        self.file.sync_all()
    }

    fn create_exclusive(&self, name: &str) -> io::Result<File> {
        let file = open_beneath(
            self.fd(),
            OsStr::new(name),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            PRIVATE_FILE_MODE,
        )?;
        fchmod(&file, PRIVATE_FILE_MODE)?;
        expect_owned_regular(&file, None)?;
        Ok(file)
    }

    fn open_regular(
        &self,
        name: &str,
        flags: libc::c_int,
        expected: Option<FileInode>,
    ) -> io::Result<File> {
        let file = open_beneath(self.fd(), OsStr::new(name), flags, 0)?;
        expect_owned_regular(&file, expected)?;
        Ok(file)
    }

    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

fn walk(path: &Path, create: bool) -> io::Result<SecureDir> {
    let process = current_process_identity();
    let (start, components, absolute) = open_start(path)?;
    validate_ancestors(&start, process)?;
    if components.is_empty() {
        return Err(invalid_storage_path());
    }
    let mut current = start;
    let last = components.len() - 1;
    for (index, name) in components.iter().enumerate() {
        current = step(&current, name, process, create, index == last, absolute)?;
    }
    Ok(current)
}

fn open_start(path: &Path) -> io::Result<(SecureDir, Vec<OsString>, bool)> {
    let mut components = Vec::new();
    let mut absolute = false;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::ParentDir => return Err(invalid_storage_path()),
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::Normal(name) => components.push(name.to_os_string()),
        }
    }
    let start_path = if absolute {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let start = open_dir_path(start_path)?;
    Ok((start, components, absolute))
}

fn validate_ancestors(start: &SecureDir, process: ProcessIdentity) -> io::Result<()> {
    let mut current = start.file.try_clone()?;
    loop {
        let identity = identity_of(&current)?;
        if !ancestor_directory_trusted(identity, process) {
            return Err(invalid_storage_path());
        }
        let parent = open_ancestor(&current)?;
        if same_file(&current, &parent.file)? {
            return Ok(());
        }
        current = parent.file;
    }
}

fn step(
    parent: &SecureDir,
    name: &OsStr,
    process: ProcessIdentity,
    create: bool,
    is_leaf: bool,
    absolute: bool,
) -> io::Result<SecureDir> {
    match open_walk_dir(parent.fd(), name, absolute) {
        Ok(dir) => finish_dir(dir, process, is_leaf),
        Err(error) if error.kind() == ErrorKind::NotFound && create => {
            match mkdirat(parent.fd(), name, KEY_DIRECTORY_MODE) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => return Err(map_open_error(error)),
            }
            finish_dir(open_walk_dir(parent.fd(), name, absolute)?, process, true)
        }
        Err(error) => Err(map_open_error(error)),
    }
}

fn finish_dir(
    dir: SecureDir,
    process: ProcessIdentity,
    treat_as_leaf: bool,
) -> io::Result<SecureDir> {
    let identity = identity_of(&dir.file)?;
    if treat_as_leaf {
        if !leaf_directory_owned(identity, process) {
            return Err(invalid_storage_path());
        }
        fchmod(&dir.file, KEY_DIRECTORY_MODE)?;
        let tightened = identity_of(&dir.file)?;
        if !leaf_directory_trusted(tightened, process) {
            return Err(invalid_storage_path());
        }
    } else if !ancestor_directory_trusted(identity, process) {
        return Err(invalid_storage_path());
    }
    Ok(dir)
}

fn open_dir_path(path: &Path) -> io::Result<SecureDir> {
    let file = open_path_component(
        libc::AT_FDCWD,
        path.as_os_str(),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    Ok(SecureDir { file })
}

fn open_ancestor(current: &File) -> io::Result<SecureDir> {
    let file = open_path_component(
        current.as_raw_fd(),
        OsStr::new(".."),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    Ok(SecureDir { file })
}

fn open_walk_dir(dirfd: RawFd, name: &OsStr, absolute: bool) -> io::Result<SecureDir> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let file = if absolute {
        open_path_component(dirfd, name, flags, 0)?
    } else {
        open_beneath(dirfd, name, flags, 0)?
    };
    Ok(SecureDir { file })
}

fn expect_owned_regular(file: &File, expected: Option<FileInode>) -> io::Result<FileInode> {
    let metadata = file.metadata()?;
    let identity = identity_from_metadata(&metadata);
    let process = current_process_identity();
    if !regular_file_owned(identity, process) {
        return Err(invalid_storage_path());
    }
    let actual = inode_from_metadata(&metadata);
    if let Some(expected) = expected {
        require_same_inode(expected, actual)?;
    }
    Ok(actual)
}

fn identity_of(file: &File) -> io::Result<PathIdentity> {
    Ok(identity_from_metadata(&file.metadata()?))
}

fn identity_from_metadata(metadata: &std::fs::Metadata) -> PathIdentity {
    PathIdentity {
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
        is_dir: metadata.is_dir(),
        is_symlink: metadata.file_type().is_symlink(),
        is_regular_file: metadata.is_file(),
    }
}

fn inode_from_metadata(metadata: &std::fs::Metadata) -> FileInode {
    FileInode {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}

fn same_file(left: &File, right: &File) -> io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

struct DirStream(*mut libc::DIR);

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: fdopendir 成功后由 closedir 释放 DIR 与 dup fd。
        unsafe { libc::closedir(self.0) };
    }
}

fn list_dir(dir: &File) -> io::Result<Vec<SecureDirEntry>> {
    // SAFETY: dup 出的 fd 交给 fdopendir；失败时自行 close，成功后 closedir 负责释放。
    let dup = unsafe { libc::dup(dir.as_raw_fd()) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    let dirp = unsafe { libc::fdopendir(dup) };
    if dirp.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(dup) };
        return Err(error);
    }
    let dirp = DirStream(dirp);
    let dir_dev = dir.metadata()?.dev();
    let mut entries = Vec::new();
    loop {
        // readdir 失败用 ? 退出，已收集的前缀随 entries drop，不当成完整清单。
        let Some(entry) = readdir(dirp.0)? else {
            break;
        };
        // SAFETY: d_name 是 dirent 内的 NUL 结尾数组；指针在下次 readdir/closedir 前有效。
        let raw = unsafe { CStr::from_ptr((*entry.as_ptr()).d_name.as_ptr()) };
        let name = OsStr::from_bytes(raw.to_bytes());
        if name == "." || name == ".." {
            continue;
        }
        let Some(name) = name.to_str() else {
            continue;
        };
        entries.push(SecureDirEntry {
            name: name.to_owned(),
            inode: FileInode {
                dev: dir_dev,
                ino: unsafe { (*entry.as_ptr()).d_ino } as u64,
            },
        });
    }
    Ok(entries)
}

/// 仅测试：按指定 inode 期望读文件，覆盖替换竞态。
#[cfg(test)]
pub(crate) fn read_named_for_test(
    directory: &Path,
    name: &str,
    expected: FileInode,
) -> io::Result<SecureFileData> {
    SecureDir::open(directory)?.read_named_limited(name, Some(expected), None)
}

#[cfg(test)]
pub(crate) fn list_for_test(directory: &Path) -> io::Result<Vec<SecureDirEntry>> {
    SecureDir::open(directory)?.list()
}

#[cfg(test)]
pub(crate) fn inode_of_path(path: &Path) -> io::Result<FileInode> {
    let metadata = std::fs::symlink_metadata(path)?;
    Ok(inode_from_metadata(&metadata))
}
