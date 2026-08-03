use std::{
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Write},
    path::Path,
};

use uuid::Uuid;

pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;
pub(crate) const KEY_DIRECTORY_MODE: u32 = 0o700;

pub(crate) fn ensure_secure_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(invalid_storage_path());
    }
    set_mode(path, KEY_DIRECTORY_MODE)
}

pub(crate) fn secure_existing_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(invalid_storage_path());
    }
    set_mode(path, PRIVATE_FILE_MODE)
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8], replace_existing: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => secure_existing_file(path)?,
        Ok(_) => return Err(invalid_storage_path()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let parent = path.parent().ok_or_else(invalid_storage_path)?;
    let temporary = parent.join(format!(".chenxing-key-{}.tmp", Uuid::new_v4().simple()));
    let result = write_temporary(&temporary, path, contents, replace_existing);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn modified_time(path: &Path) -> io::Result<std::time::SystemTime> {
    secure_existing_file(path)?;
    fs::metadata(path)?.modified()
}

fn write_temporary(
    temporary: &Path,
    destination: &Path,
    contents: &[u8],
    replace_existing: bool,
) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, PRIVATE_FILE_MODE);
    let mut file = options.open(temporary)?;
    set_file_mode(&file)?;
    file.write_all(contents)?;
    file.sync_all()?;

    if replace_existing {
        fs::rename(temporary, destination)?;
    } else {
        fs::hard_link(temporary, destination)?;
        let _ = fs::remove_file(temporary);
    }
    sync_directory(destination.parent());
    Ok(())
}

fn sync_directory(_path: Option<&Path>) {
    #[cfg(unix)]
    if let Some(path) = path
        && let Ok(directory) = File::open(path)
    {
        let _ = directory.sync_all();
    }
}

fn set_file_mode(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn invalid_storage_path() -> io::Error {
    io::Error::new(ErrorKind::PermissionDenied, "invalid secure storage path")
}
