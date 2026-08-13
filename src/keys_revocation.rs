//! 吊销：把某个 `kid` 从签名与验证集合中移除，必要时切换 active key。
//!
//! 吊销 active key 要同时改动两处磁盘事实（active kid 与私钥材料），因此磁盘部分
//! 不在这里手写顺序，而是交给 `journal`：先把意图落盘，再由同一个恢复函数执行。
//! 崩溃恢复走的是完全相同的代码路径，不存在第二份补偿逻辑（Issue #284）。
//!
//! journal 记录落盘即是提交点：此后即使立即收敛被瞬时 IO 失败打断，内存也必须
//! 切换到不含被吊销 key 的计划快照，绝不能继续用它签发——本实例签出的 token 在
//! 其余已收敛的实例上会全部验不过（Issue #315）。

use std::{collections::BTreeMap, path::Path, time::Duration};

use time::OffsetDateTime;

use crate::key_storage::{KeyStorageLock, ensure_secure_directory};

use super::{
    KeyManager, KeyManagerError, KeyMaterial, KeyRevocation, KeyState, build_key_state, journal,
    persistence,
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
    let planned_active_key_id = if active_key_id == key_id {
        newest_key_id(&materials).ok_or(KeyManagerError::NoActiveKeyReplacement)?
    } else {
        active_key_id.clone()
    };
    // 吊销 active key 时替代者是一个已退役的 key，它从这一刻起重新在役，因此必须
    // 清掉它的退役时刻。留着会让它下次退役时沿用上一轮的起点，保留窗口被提前用掉
    // （Issue #298）。磁盘侧的记录由 `commit_to_disk` 之后的加载 reconcile 清除，
    // 内存这份要就地改，否则本实例在下次加载前一直带着错误的窗口起点。
    if let Some(material) = materials.get_mut(&planned_active_key_id) {
        material.retired_at = None;
    }
    // 先验证计划快照中的每份材料，避免 journal 落盘后才发现某个公钥无法构造。
    let planned_state = build_key_state(
        directory.clone(),
        retention,
        planned_active_key_id.clone(),
        materials,
    )?;
    let (next_active_key_id, next_state) = match directory.as_ref() {
        Some(directory) => snapshot_after_commit(
            directory,
            retention,
            &planned_active_key_id,
            planned_state,
            commit_to_disk(directory, retention, now, &key_id, &planned_active_key_id)?,
        )?,
        None => (planned_active_key_id, planned_state),
    };

    // 快照选择见 `snapshot_after_commit`：无论磁盘是否立即收敛，这里发布的快照都
    // 不再包含被吊销的 key，不会把已吊销的密钥留在签发热路径上（Issue #315）。
    let published_key_count = next_state.jwks.keys.len();
    *manager.write_state() = next_state;
    Ok(KeyRevocation {
        key_id,
        active_key_id: next_active_key_id,
        published_key_count,
    })
}

/// 一次吊销提交到磁盘后的收敛结果。
pub(super) enum CommitOutcome {
    /// 磁盘已完全收敛到吊销后的快照。
    Converged(String, BTreeMap<String, KeyMaterial>),
    /// 吊销已提交（journal 记录已落盘），但本次立即收敛被瞬时 IO 失败打断；
    /// 恢复会在下一次加载继续执行。
    Pending,
}

/// 决定吊销提交后发布的内存快照与 active kid。
///
/// 磁盘收敛成功时发布读回的实际快照，失败时发布计划快照：吊销已经提交，内存
/// 绝不能继续把被吊销的 key 当作 active 签发，否则其余已收敛的实例会拒绝这批
/// token（Issue #315）。计划快照与 journal 意图一致，磁盘由下一次加载补完，
/// 后台同步随后把内存对齐到最终事实。
pub(super) fn snapshot_after_commit(
    directory: &Path,
    retention: Duration,
    planned_active_key_id: &str,
    planned_state: KeyState,
    outcome: CommitOutcome,
) -> Result<(String, KeyState), KeyManagerError> {
    match outcome {
        CommitOutcome::Converged(disk_active_key_id, disk_materials) => {
            let state = if planned_state.matches_disk_snapshot(&disk_active_key_id, &disk_materials)
            {
                planned_state
            } else {
                // 仅异常恢复会走这里：以 journal 收敛后的实际 active/materials 为准，
                // 不能发布调用前推算的陈旧快照。
                build_key_state(
                    Some(directory.to_path_buf()),
                    retention,
                    disk_active_key_id.clone(),
                    disk_materials,
                )?
            };
            Ok((disk_active_key_id, state))
        }
        CommitOutcome::Pending => Ok((planned_active_key_id.to_owned(), planned_state)),
    }
}

/// 落盘一次吊销：写意图记录，随后立即执行恢复流程把它做完。
///
/// 刻意不在这里手写"先写 kid 再删材料"的顺序，而是复用 `journal::recover`：
/// 正常路径与重启恢复因此共用同一段实现，顺序约束只需要在一处正确。
///
/// 记录落盘即视为提交：`Err` 只可能来自记录写入之前，此时磁盘没有任何改动；
/// 记录写入之后即使收敛失败，吊销也已经决定，返回 `CommitOutcome::Pending`，
/// 由下一次加载继续收敛。调用方对 Pending 必须发布计划快照，不得继续用被吊销
/// 的 key 签发（Issue #315）。
fn commit_to_disk(
    directory: &Path,
    retention: Duration,
    now: OffsetDateTime,
    revoked_key_id: &str,
    next_active_key_id: &str,
) -> Result<CommitOutcome, KeyManagerError> {
    let pending =
        journal::PendingRevocation::new(revoked_key_id.to_owned(), next_active_key_id.to_owned());
    journal::record(directory, &pending)?;
    match persistence::load_materials(directory, retention, now, false) {
        Ok((active_key_id, key_files)) => Ok(CommitOutcome::Converged(active_key_id, key_files)),
        Err(error) => {
            tracing::warn!(
                key_id = %revoked_key_id,
                replacement_key_id = %next_active_key_id,
                error = %error,
                "revocation committed but the key directory did not converge; \
                 publishing the planned snapshot and retrying convergence on the next load"
            );
            Ok(CommitOutcome::Pending)
        }
    }
}

fn newest_key_id(materials: &BTreeMap<String, KeyMaterial>) -> Option<String> {
    materials
        .iter()
        .max_by_key(|(_, material)| material.created_at)
        .map(|(key_id, _)| key_id.clone())
}
