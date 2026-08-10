//! 吊销：把某个 `kid` 从签名与验证集合中移除，必要时切换 active key。
//!
//! 吊销 active key 要同时改动两处磁盘事实（active kid 与私钥材料），因此磁盘部分
//! 不在这里手写顺序，而是交给 `journal`：先把意图落盘，再由同一个恢复函数执行。
//! 崩溃恢复走的是完全相同的代码路径，不存在第二份补偿逻辑（Issue #284）。

use std::collections::BTreeMap;

use time::OffsetDateTime;

use crate::key_storage::{KeyStorageLock, ensure_secure_directory};

use super::{
    KeyManager, KeyManagerError, KeyMaterial, KeyRevocation, build_key_state, journal, persistence,
};

pub(super) fn revoke_blocking_at(
    manager: &KeyManager,
    key_id: String,
    now: OffsetDateTime,
) -> Result<KeyRevocation, KeyManagerError> {
    persistence::validate_key_id(&key_id)?;

    let _rotation_guard = manager
        .rotation_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (directory, retention, mut active_key_id, mut materials) = {
        let state = manager.read_state();
        (
            state.directory.clone(),
            state.retention,
            state.active_key_id.clone(),
            state.private_materials.clone(),
        )
    };

    if let Some(directory) = directory.as_ref() {
        ensure_secure_directory(directory)?;
    }
    let _storage_lock = match directory.as_ref() {
        Some(directory) => Some(KeyStorageLock::acquire(directory)?),
        None => None,
    };
    if let Some(directory) = directory.as_ref() {
        // 这次加载同时完成崩溃遗留的半成品吊销，因此下面看到的是一份已收敛的快照。
        let (disk_active_key_id, disk_materials) =
            persistence::load_materials(directory, retention, now, false)?;
        active_key_id = disk_active_key_id;
        materials = disk_materials;
    }

    if !materials.contains_key(&key_id) {
        return Err(KeyManagerError::UnknownKeyId);
    }
    let _ = materials.remove(&key_id);
    let next_active_key_id = if active_key_id == key_id {
        newest_key_id(&materials).ok_or(KeyManagerError::NoActiveKeyReplacement)?
    } else {
        active_key_id.clone()
    };
    let next_state = build_key_state(
        directory.clone(),
        retention,
        next_active_key_id.clone(),
        materials,
    )?;

    if let Some(directory) = directory.as_ref() {
        commit_to_disk(directory, &key_id, &next_active_key_id)?;
    }

    // 只有磁盘完全收敛后才替换内存快照。失败时内存保持吊销前状态，与磁盘一致：
    // 磁盘上要么完全没变，要么留着待完成的记录，下一次加载会把它补完。
    let published_key_count = next_state.jwks.keys.len();
    *manager.write_state() = next_state;
    Ok(KeyRevocation {
        key_id,
        active_key_id: next_active_key_id,
        published_key_count,
    })
}

/// 落盘一次吊销：写意图记录，随后立即执行恢复流程把它做完。
///
/// 刻意不在这里手写"先写 kid 再删材料"的顺序，而是复用 `journal::recover`：
/// 正常路径与重启恢复因此共用同一段实现，顺序约束只需要在一处正确。
///
/// 记录落盘即视为提交。`recover` 失败时返回错误、不改内存，但记录仍在盘上，
/// 下一次加载（重启、后台同步或再次吊销）会重新执行同样的步骤，最终收敛到
/// 吊销完成——已提交的吊销不会因为一次瞬时 IO 失败而悄悄回退。
fn commit_to_disk(
    directory: &std::path::Path,
    revoked_key_id: &str,
    next_active_key_id: &str,
) -> Result<(), KeyManagerError> {
    let pending =
        journal::PendingRevocation::new(revoked_key_id.to_owned(), next_active_key_id.to_owned());
    journal::record(directory, &pending)?;
    if let Err(error) = journal::recover(directory) {
        tracing::error!(
            key_id = %revoked_key_id,
            replacement_key_id = %next_active_key_id,
            error = %error,
            "failed to complete a committed key revocation; \
             it will be retried on the next key directory load"
        );
        return Err(error);
    }
    Ok(())
}

fn newest_key_id(materials: &BTreeMap<String, KeyMaterial>) -> Option<String> {
    materials
        .iter()
        .max_by_key(|(_, material)| material.created_at)
        .map(|(key_id, _)| key_id.clone())
}
