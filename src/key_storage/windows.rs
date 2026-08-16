//! Windows 密钥目录：沿路径用目录句柄 + NtCreateFile 前进，打开后校验。
//!
//! 路径级 `CreateFile` 再检查有 TOCTOU。这里每一步都绑定已验证的目录句柄，
//! 最终分量带 `FILE_OPEN_REPARSE_POINT`。已有宽松/外来 DACL fail-closed，
//! 只在我们自己创建的对象上写入受保护 ACL。

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, ErrorKind, Read, Write},
    path::{Component, Path, PathBuf},
};

use super::policy::{FileInode, invalid_storage_path, require_same_inode};
use super::windows_acl::{ProtectedSd, TrustedSids, apply_protected_dacl, validate_leaf_dacl};
use super::windows_policy::{
    ancestor_kind_trusted, leaf_directory_kind_trusted, regular_file_kind_trusted,
};
use super::windows_sys::{
    dir_access, dispose_file, file_read_access, file_write_access, inode_of, list_dir,
    open_dir_path, open_relative, path_kind, raw_handle, rename_in_dir, require_kind,
};
use super::{SecureFileData, TEMPORARY_FILE_SUFFIX, TemporaryFileKind};

pub(crate) struct SecureDir {
    file: File,
}

#[derive(Debug)]
pub(crate) struct SecureDirEntry {
    pub name: String,
    pub inode: FileInode,
}

impl SecureDir {
    pub(crate) fn ensure(path: &Path) -> io::Result<Self> {
        walk(path, true)
    }

    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        walk(path, false)
    }

    pub(crate) fn list(&self) -> io::Result<Vec<SecureDirEntry>> {
        Ok(list_dir(&self.file)?
            .into_iter()
            .map(|entry| SecureDirEntry {
                name: entry.name,
                inode: entry.inode,
            })
            .collect())
    }

    pub(crate) fn read_named_limited(
        &self,
        name: &str,
        expected: Option<FileInode>,
        max_bytes: Option<u64>,
    ) -> io::Result<SecureFileData> {
        let file = self.open_regular(name, file_read_access(), expected)?;
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
        match self.open_regular(name, file_read_access(), None) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn remove_regular_file(&self, name: &str) -> io::Result<()> {
        let file = self.open_regular(name, file_write_access(), None)?;
        dispose_file(&file)
    }

    pub(crate) fn atomic_write(
        &self,
        kind: TemporaryFileKind,
        name: &str,
        contents: &[u8],
        replace_existing: bool,
    ) -> io::Result<()> {
        match self.open_regular(name, file_read_access(), None) {
            Ok(_) => {
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
            if let Ok(file) = self.open_regular(&temporary, file_write_access(), None) {
                let _ = dispose_file(&file);
            }
        }
        result
    }

    pub(crate) fn open_or_create(&self, name: &str) -> io::Result<File> {
        match self.open_regular(name, file_write_access(), None) {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                match self.create_exclusive(name) {
                    Ok(file) => Ok(file),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                        self.open_regular(name, file_write_access(), None)
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
        rename_in_dir(&file, &self.file, destination, replace_existing)?;
        drop(file);
        Ok(())
    }

    fn create_exclusive(&self, name: &str) -> io::Result<File> {
        let sids = TrustedSids::load()?;
        let sd = ProtectedSd::for_file(&sids)?;
        let file = open_relative(
            &self.file,
            OsStr::new(name),
            file_write_access(),
            false,
            true,
            Some(&sd),
        )?;
        require_regular(&file, None)?;
        apply_protected_dacl(raw_handle(&file), &sids, false)?;
        validate_leaf_dacl(raw_handle(&file), &sids)?;
        Ok(file)
    }

    fn open_regular(
        &self,
        name: &str,
        access: u32,
        expected: Option<FileInode>,
    ) -> io::Result<File> {
        let file = open_relative(&self.file, OsStr::new(name), access, false, false, None)?;
        require_regular(&file, expected)?;
        Ok(file)
    }
}

fn walk(path: &Path, create: bool) -> io::Result<SecureDir> {
    let (start, components) = open_start(path)?;
    if components.is_empty() {
        return Err(invalid_storage_path());
    }
    let mut current = start;
    let last = components.len() - 1;
    for (index, name) in components.iter().enumerate() {
        current = step(&current, name, create, index == last)?;
    }
    Ok(current)
}

fn open_start(path: &Path) -> io::Result<(SecureDir, Vec<OsString>)> {
    let mut components = Vec::new();
    let mut start = PathBuf::new();
    let mut absolute = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => start.push(prefix.as_os_str()),
            Component::RootDir => {
                absolute = true;
                start.push(std::path::MAIN_SEPARATOR_STR);
            }
            Component::CurDir => {}
            Component::ParentDir => return Err(invalid_storage_path()),
            Component::Normal(name) => components.push(name.to_os_string()),
        }
    }
    let start_path = if absolute {
        start.as_path()
    } else {
        Path::new(".")
    };
    let file = open_dir_path(start_path)?;
    require_kind(&file, true)?;
    if !ancestor_kind_trusted(path_kind(&file)?) {
        return Err(invalid_storage_path());
    }
    Ok((SecureDir { file }, components))
}

fn step(parent: &SecureDir, name: &OsStr, create: bool, is_leaf: bool) -> io::Result<SecureDir> {
    match open_relative(&parent.file, name, dir_access(), true, false, None) {
        Ok(dir) => finish_dir(dir, is_leaf, false),
        Err(error) if error.kind() == ErrorKind::NotFound && create => {
            match create_dir(parent, name) {
                Ok(dir) => finish_dir(dir, true, true),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => finish_dir(
                    open_relative(&parent.file, name, dir_access(), true, false, None)?,
                    is_leaf,
                    false,
                ),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn create_dir(parent: &SecureDir, name: &OsStr) -> io::Result<File> {
    let sids = TrustedSids::load()?;
    let sd = ProtectedSd::for_directory(&sids)?;
    let file = open_relative(&parent.file, name, dir_access(), true, true, Some(&sd))?;
    apply_protected_dacl(raw_handle(&file), &sids, true)?;
    Ok(file)
}

fn finish_dir(file: File, treat_as_leaf: bool, just_created: bool) -> io::Result<SecureDir> {
    let kind = require_kind(&file, true)?;
    if treat_as_leaf {
        if !leaf_directory_kind_trusted(kind) {
            return Err(invalid_storage_path());
        }
        let sids = TrustedSids::load()?;
        if just_created {
            apply_protected_dacl(raw_handle(&file), &sids, true)?;
        }
        validate_leaf_dacl(raw_handle(&file), &sids)?;
    } else if !ancestor_kind_trusted(kind) {
        return Err(invalid_storage_path());
    }
    Ok(SecureDir { file })
}

fn require_regular(file: &File, expected: Option<FileInode>) -> io::Result<FileInode> {
    let kind = require_kind(file, false)?;
    if !regular_file_kind_trusted(kind) {
        return Err(invalid_storage_path());
    }
    let sids = TrustedSids::load()?;
    validate_leaf_dacl(raw_handle(file), &sids)?;
    let actual = inode_of(file)?;
    if let Some(expected) = expected {
        require_same_inode(expected, actual)?;
    }
    Ok(actual)
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
    let (parent, name) = super::split_dir_and_name(path)?;
    let dir = SecureDir::open(parent)?;
    let file = dir.open_regular(name, file_read_access(), None)?;
    inode_of(&file)
}

#[cfg(test)]
pub(crate) fn apply_loose_acl_for_test(path: &Path) -> io::Result<()> {
    let file = open_dir_path(path)?;
    super::windows_acl::apply_allow_everyone_for_test(raw_handle(&file))
}

#[cfg(test)]
pub(crate) fn apply_foreign_acl_for_test(path: &Path) -> io::Result<()> {
    let file = open_dir_path(path)?;
    super::windows_acl::apply_foreign_principal_for_test(raw_handle(&file))
}
