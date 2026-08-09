use std::{collections::BTreeMap, fs, path::Path, time::Duration};

use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::key_storage::{
    atomic_write, cleanup_stale_temporary_files, ensure_secure_directory, modified_time,
    remove_secure_file, secure_existing_file,
};

use super::{
    KeyManagerError, KeyMaterial, generate_rsa_key, key_material, prune_materials,
    within_retention_at,
};

const ACTIVE_KEY_ID_FILE: &str = "active-rs256.kid";
const LEGACY_KEY_FILE: &str = "active-rs256.pkcs1.der";
const KEY_FILE_PREFIX: &str = "rs256-";
const KEY_FILE_SUFFIX: &str = ".pkcs1.der";

/// 在共享目录锁内读取一份完整的密钥快照。
///
/// `active-rs256.kid` 只决定选择哪个材料，私钥材料本身始终从同一份
/// `key_files` 快照构造，调用方不会再分别读取 kid 和私钥。
pub(super) fn load_materials(
    directory: &Path,
    retention: Duration,
    now: OffsetDateTime,
    generate_if_empty: bool,
) -> Result<(String, BTreeMap<String, KeyMaterial>), KeyManagerError> {
    ensure_secure_directory(directory)?;
    cleanup_stale_temporary_files(directory)?;
    let active_id_path = directory.join(ACTIVE_KEY_ID_FILE);
    let declared_active_id = read_optional_key_id(&active_id_path)?;
    cleanup_expired_key_files(directory, declared_active_id.as_deref(), retention, now)?;
    let mut key_files = discover_key_files(directory)?;

    let migrated_id = if key_files.is_empty() {
        migrate_legacy_key(
            directory,
            declared_active_id.as_deref(),
            &mut key_files,
            now,
        )?
    } else {
        remove_legacy_key(directory)?;
        None
    };

    // 只有四种合法出口，其余组合一律 fail-closed。关键区分是"kid 存在但它指向的材料
    // 不在盘上"：这不是首次初始化，而是私钥丢失或目录被破坏。此时生成替代密钥会静默
    // 作废所有已签发令牌、把 JWKS 换成全新公钥，并覆盖唯一还能指认丢失材料的证据
    // （kid 文件本身），使故障无法追溯。
    let newest_id = newest_key_id(&key_files);
    let active_key_id = match (migrated_id, declared_active_id, newest_id) {
        // 迁移刚刚落盘并写好 kid，材料就是它自己。
        (Some(key_id), _, _) => key_id,
        // 正常路径：kid 指向的材料在盘上。
        (None, Some(key_id), _) if key_files.contains_key(&key_id) => key_id,
        // kid 指向的材料丢失或损坏：fail-closed，不改盘上任何字节。
        (None, Some(key_id), _) => {
            tracing::error!(
                active_key_id = %key_id,
                discovered_key_count = key_files.len(),
                "active signing key material is missing from the key directory; \
                 refusing to overwrite the active key id or generate a replacement"
            );
            return Err(KeyManagerError::MissingActiveKeyMaterial);
        }
        // kid 文件丢失但材料仍在：可以从材料自身恢复，不作废任何已签发令牌。
        (None, None, Some(key_id)) => {
            tracing::warn!(
                active_key_id = %key_id,
                discovered_key_count = key_files.len(),
                "active key id file is missing; adopting the newest persisted signing key"
            );
            persist_active_key_id(directory, &key_id)?;
            key_id
        }
        // 真正的空目录：既没有 kid 也没有任何材料，才允许首次初始化。
        (None, None, None) => {
            if !generate_if_empty {
                return Err(KeyManagerError::MissingActiveKeyMaterial);
            }
            initialize_first_key(directory, &mut key_files)?
        }
    };

    prune_materials(
        Some(directory),
        &active_key_id,
        &mut key_files,
        retention,
        now,
    );
    // prune_materials 永不删除 active key，这里只是守住该不变量。
    if !key_files.contains_key(&active_key_id) {
        return Err(KeyManagerError::MissingActiveKeyMaterial);
    }
    Ok((active_key_id, key_files))
}

/// 空目录的首次初始化：生成、落盘并写入 kid。
fn initialize_first_key(
    directory: &Path,
    key_files: &mut BTreeMap<String, KeyMaterial>,
) -> Result<String, KeyManagerError> {
    let (key_id, der) = generate_rsa_key()?;
    persist_key(directory, &key_id, &der)?;
    let created_at = OffsetDateTime::from(modified_time(&directory.join(key_file_name(&key_id)))?);
    persist_active_key_id(directory, &key_id)?;
    key_files.insert(key_id.clone(), key_material(der, created_at));
    Ok(key_id)
}

fn discover_key_files(directory: &Path) -> Result<BTreeMap<String, KeyMaterial>, KeyManagerError> {
    let mut keys = BTreeMap::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.starts_with(KEY_FILE_PREFIX) || !file_name.ends_with(KEY_FILE_SUFFIX) {
            continue;
        }
        let key_id = file_name
            .strip_prefix(KEY_FILE_PREFIX)
            .and_then(|value| value.strip_suffix(KEY_FILE_SUFFIX))
            .ok_or(KeyManagerError::InvalidKeyId)?
            .to_owned();
        validate_key_id(&key_id)?;
        let created_at = OffsetDateTime::from(modified_time(&path)?);
        let der = Zeroizing::new(fs::read(path)?);
        keys.insert(key_id, key_material(der, created_at));
    }
    Ok(keys)
}

pub(super) fn cleanup_expired_key_files(
    directory: &Path,
    active_key_id: Option<&str>,
    retention: Duration,
    now: OffsetDateTime,
) -> Result<(), KeyManagerError> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.starts_with(KEY_FILE_PREFIX) || !file_name.ends_with(KEY_FILE_SUFFIX) {
            continue;
        }
        let key_id = file_name
            .strip_prefix(KEY_FILE_PREFIX)
            .and_then(|value| value.strip_suffix(KEY_FILE_SUFFIX))
            .ok_or(KeyManagerError::InvalidKeyId)?;
        validate_key_id(key_id)?;
        let created_at = OffsetDateTime::from(modified_time(&path)?);
        if active_key_id != Some(key_id) && !within_retention_at(created_at, retention, now) {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

/// 迁移旧版单文件私钥。返回迁移后落盘的 key id；没有旧文件时返回 `None`。
///
/// 返回值让调用方区分"kid 指向的材料由本次迁移刚刚补齐"和"kid 指向的材料确实丢失"，
/// 迁移路径因此不需要再次从盘上读回 kid。
fn migrate_legacy_key(
    directory: &Path,
    declared_active_id: Option<&str>,
    key_files: &mut BTreeMap<String, KeyMaterial>,
    now: OffsetDateTime,
) -> Result<Option<String>, KeyManagerError> {
    let legacy_path = directory.join(LEGACY_KEY_FILE);
    let metadata = match fs::symlink_metadata(&legacy_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid secure storage path",
        )
        .into());
    }
    secure_existing_file(&legacy_path)?;
    let key_id = match declared_active_id {
        Some(value) => value.to_owned(),
        None => format!("cx-{}", uuid::Uuid::new_v4().simple()),
    };
    validate_key_id(&key_id)?;
    let der = Zeroizing::new(fs::read(&legacy_path)?);
    persist_key(directory, &key_id, &der)?;
    persist_active_key_id(directory, &key_id)?;
    fs::remove_file(&legacy_path)?;
    key_files.insert(key_id.clone(), key_material(der, now));
    Ok(Some(key_id))
}

fn remove_legacy_key(directory: &Path) -> Result<(), KeyManagerError> {
    let legacy_path = directory.join(LEGACY_KEY_FILE);
    match fs::symlink_metadata(&legacy_path) {
        Ok(metadata) if metadata.is_file() => {
            secure_existing_file(&legacy_path)?;
            fs::remove_file(legacy_path)?;
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid secure storage path",
            )
            .into());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(super) fn persist_key(
    directory: &Path,
    key_id: &str,
    der: &[u8],
) -> Result<(), KeyManagerError> {
    validate_key_id(key_id)?;
    atomic_write(&directory.join(key_file_name(key_id)), der, false)?;
    Ok(())
}

pub(super) fn remove_key(directory: &Path, key_id: &str) -> Result<(), KeyManagerError> {
    validate_key_id(key_id)?;
    remove_secure_file(&directory.join(key_file_name(key_id)))?;
    Ok(())
}

pub(super) fn persist_active_key_id(directory: &Path, key_id: &str) -> Result<(), KeyManagerError> {
    validate_key_id(key_id)?;
    atomic_write(&directory.join(ACTIVE_KEY_ID_FILE), key_id.as_bytes(), true)?;
    Ok(())
}

fn read_optional_key_id(path: &Path) -> Result<Option<String>, KeyManagerError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Err(KeyManagerError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid secure storage path",
        )));
    }
    secure_existing_file(path)?;
    let key_id = fs::read_to_string(path)?.trim().to_owned();
    validate_key_id(&key_id)?;
    Ok(Some(key_id))
}

fn newest_key_id(key_files: &BTreeMap<String, KeyMaterial>) -> Option<String> {
    key_files
        .iter()
        .max_by_key(|(_, material)| material.created_at)
        .map(|(key_id, _)| key_id.clone())
}

pub(super) fn key_file_name(key_id: &str) -> String {
    format!("{KEY_FILE_PREFIX}{key_id}{KEY_FILE_SUFFIX}")
}

pub(super) fn validate_key_id(key_id: &str) -> Result<(), KeyManagerError> {
    if key_id.is_empty()
        || !key_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '_'
        })
    {
        return Err(KeyManagerError::InvalidKeyId);
    }
    Ok(())
}

#[cfg(test)]
#[path = "keys_persistence_tests.rs"]
mod tests;
