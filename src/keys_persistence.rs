use std::{collections::BTreeMap, fs, path::Path, time::Duration};

use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::key_storage::{
    atomic_write, cleanup_stale_temporary_files, ensure_secure_directory, modified_time,
    remove_secure_file, secure_existing_file,
};

use super::{
    KeyManagerError, KeyMaterial, generate_rsa_key, journal, key_material, prune_materials,
    retirement,
};

pub(super) const ACTIVE_KEY_ID_FILE: &str = "active-rs256.kid";
const LEGACY_KEY_FILE: &str = "active-rs256.pkcs1.der";
pub(super) const KEY_FILE_PREFIX: &str = "rs256-";
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
    // 必须早于读取 kid 和发现材料：崩溃留下的半成品吊销会在这里被补完，之后所有
    // 判断看到的都是一份已收敛的目录。否则被吊销的材料会被 discover_key_files
    // 读回内存并重新发布进 JWKS（Issue #284）。
    journal::recover(directory)?;
    let declared_active_id = declared_active_key_id(directory)?;
    // 先把材料连同退役时刻整份读进来，再判断谁是 active、谁过期。过期判定必须在
    // 确定 active kid 之后进行：`declared_active_id` 可能缺失，此时 active 由最新
    // 材料推定，用它之前的值裁剪会误删真正的 active key（Issue #298）。
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

    // 落实“active key 没有退役记录，其余都有记录”这条不变量后再裁剪：升级前的历史
    // 目录和崩溃遗留的半成品都在这里自愈，因此下面的裁剪对每个非 active key 都有
    // 明确的退役时刻可用，不需要退回按创建时刻推断。
    retirement::reconcile(directory, &active_key_id, &mut key_files, now)?;
    let expired = prune_materials(&active_key_id, &mut key_files, retention, now);
    remove_expired_key_files(directory, &expired);
    // prune_materials 永不删除 active key，这里只是守住该不变量。
    if !key_files.contains_key(&active_key_id) {
        return Err(KeyManagerError::MissingActiveKeyMaterial);
    }
    Ok((active_key_id, key_files))
}

/// 删除已越过保留窗口的密钥材料与其退役记录。
///
/// 判据来自 `prune_materials`：内存里已经不再发布这些 `kid`，磁盘删除只是回收。
/// 因此单个文件删不掉时告警继续，而不是让整个加载失败——公钥已经下线，残留文件
/// 会在下一次加载被重新发现、重新判定过期、再次尝试删除，不会重新进入 JWKS。
fn remove_expired_key_files(directory: &Path, expired: &[String]) {
    for key_id in expired {
        if let Err(error) = remove_key(directory, key_id) {
            tracing::warn!(
                key_id = %key_id,
                error = %error,
                "failed to reclaim an expired signing key file"
            );
        }
    }
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
        let mut material = key_material(der, created_at);
        retirement::load_into(directory, &key_id, &mut material)?;
        keys.insert(key_id, material);
    }
    Ok(keys)
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

/// 删除私钥材料及其退役记录。材料已不存在同样算成功。
///
/// 幂等是吊销恢复路径的前提：`journal::recover` 可能在材料已被删除、只剩记录
/// 未清除时再跑一次，此时把 `NotFound` 当错误会让目录永远卡在待恢复状态。
///
/// 记录随材料一起删除，否则目录里会积累无主的退役记录，让运维误以为某个 `kid`
/// 仍在保留窗口内。先删材料：材料是凭据，记录只是元数据，中间崩溃留下的孤立记录
/// 由 `retirement::reconcile` 收拾。
pub(super) fn remove_key(directory: &Path, key_id: &str) -> Result<(), KeyManagerError> {
    validate_key_id(key_id)?;
    match remove_secure_file(&directory.join(key_file_name(key_id))) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    retirement::clear(directory, key_id)
}

/// 丢弃所有可发现的持久化私钥材料。
///
/// 仅用于 journal 损坏的恢复路径。记录没有完整性校验，保留任何旧 key 都可能把真正
/// 已吊销的 key 重新发布；删除整个 keyset 虽会使旧 token 失效，却是唯一不猜测私钥
/// 身份的安全收敛方式。路径来自目录枚举，内容从不读入内存或日志。
pub(super) fn discard_all_key_material(directory: &Path) -> Result<(), KeyManagerError> {
    let mut key_paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let is_current_key = file_name.starts_with(KEY_FILE_PREFIX)
            && file_name.ends_with(KEY_FILE_SUFFIX);
        if is_current_key || file_name == LEGACY_KEY_FILE {
            key_paths.push(path);
        }
    }
    for path in key_paths {
        match remove_secure_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// 为 journal 恢复建立一个明确存在的 active key，且永不选择 `revoked_key_id`。
///
/// 优先复用最新的现存材料，避免无谓作废旧 token；没有候选才生成新 key。扫描只读取
/// 文件名与 mtime，不把私钥内容复制到恢复日志或临时容器。active 指针写好后 journal
/// 才会被调用方清除，因此中途崩溃仍可重放。
pub(super) fn establish_recovery_active_key(
    directory: &Path,
    revoked_key_id: Option<&str>,
) -> Result<String, KeyManagerError> {
    if let Some(revoked_key_id) = revoked_key_id {
        validate_key_id(revoked_key_id)?;
    }
    let mut candidates = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(key_id) = file_name
            .strip_prefix(KEY_FILE_PREFIX)
            .and_then(|value| value.strip_suffix(KEY_FILE_SUFFIX))
        else {
            continue;
        };
        validate_key_id(key_id)?;
        if Some(key_id) != revoked_key_id {
            candidates.push((modified_time(&path)?, key_id.to_owned()));
        }
    }

    if let Some((_, key_id)) = candidates.into_iter().max() {
        persist_active_key_id(directory, &key_id)?;
        retirement::clear(directory, &key_id)?;
        return Ok(key_id);
    }

    let (key_id, der) = generate_rsa_key()?;
    persist_key(directory, &key_id, &der)?;
    persist_active_key_id(directory, &key_id)?;
    Ok(key_id)
}

/// 判断某个 `kid` 的私钥材料是否在盘上，且确实是普通文件。
///
/// 非普通文件（符号链接、目录）一律报错而不是当成"不存在"：密钥目录里出现这种
/// 路径说明目录已被篡改，静默跳过会让后续写入落到攻击者可控的位置。
pub(super) fn has_key_material(directory: &Path, key_id: &str) -> Result<bool, KeyManagerError> {
    validate_key_id(key_id)?;
    match fs::symlink_metadata(directory.join(key_file_name(key_id))) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(KeyManagerError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid secure storage path",
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// 读取盘上声明的 active `kid`；文件不存在时返回 `None`。
pub(super) fn declared_active_key_id(directory: &Path) -> Result<Option<String>, KeyManagerError> {
    read_optional_key_id(&directory.join(ACTIVE_KEY_ID_FILE))
}

/// 删除失效的 active `kid` 指针。不存在同样算成功；非普通文件仍然 fail-closed。
pub(super) fn clear_active_key_id(directory: &Path) -> Result<(), KeyManagerError> {
    match remove_secure_file(&directory.join(ACTIVE_KEY_ID_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
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
