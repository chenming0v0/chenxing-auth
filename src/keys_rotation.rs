use time::OffsetDateTime;

use crate::key_storage::{KeyStorageLock, ensure_secure_directory};

use super::{
    KeyManager, KeyManagerError, KeyRotation, build_key_state, generate_rsa_key, journal,
    key_material, persistence, prune, retirement,
};

/// 轮换：生成新签名密钥，写入共享目录，并替换内存快照。
///
/// 全过程持阻塞目录锁，因此与其他实例的轮换、吊销和后台同步串行化。锁必须持有到
/// 内存写入完成：后台同步用 `try_acquire`，锁被占用时会跳过本轮，所以只要写内存
/// 仍在锁内，同步就不可能用锁前读到的旧快照覆盖刚完成的轮换（Issue #257）。
pub(super) fn rotate_blocking_at(
    manager: &KeyManager,
    now: OffsetDateTime,
) -> Result<KeyRotation, KeyManagerError> {
    let _rotation_guard = manager
        .rotation_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (directory, retention, skew_allowance, mut previous_active_key_id, mut materials) = {
        let state = manager.read_state();
        (
            state.directory.clone(),
            state.retention,
            state.skew_allowance,
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
        let (disk_active_key_id, disk_materials) =
            persistence::load_materials(directory, retention, skew_allowance, now, true)?;
        // 退役的是磁盘上当前在役的那个 key，不是本实例内存里的：别的实例可能已经
        // 轮换过，本实例的内存快照还没同步。
        previous_active_key_id = disk_active_key_id;
        materials = disk_materials;
    }

    let (key_id, der) = generate_rsa_key()?;
    // 旧 active key 从这一刻起只用于验证，保留窗口从这一刻起算（Issue #298）。
    let retired_at = prune::mark_retired(&mut materials, &previous_active_key_id, now);
    materials.insert(key_id.clone(), key_material(der.clone(), now));
    let expired = prune::prune_materials(&key_id, &mut materials, retention, skew_allowance, now);
    let next_state = build_key_state(
        directory.clone(),
        retention,
        skew_allowance,
        key_id.clone(),
        materials,
    )?;

    if let Some(directory) = directory.as_ref() {
        // 先把轮换意图落盘，再动私钥材料（Issue #318）：崩溃后加载路径据此把
        // 轮换补完或回滚，盘上不会留下从未进入 JWKS 的孤儿私钥——孤儿文件 mtime
        // 最新，会被吊销逻辑选为新签名密钥。记录失败说明目录不可写，此时轮换
        // 什么都不该发生。
        journal::record_rotation(
            directory,
            &journal::PendingRotation::new(key_id.clone(), previous_active_key_id.clone()),
        )?;
        if let Err(error) = persistence::persist_key(directory, &key_id, &der)
            .and_then(|_| persistence::persist_active_key_id(directory, &key_id))
        {
            // 回滚刚落盘的私钥材料与意图记录：active kid 没写成，轮换没有生效。
            // 删除必须与其余路径一致走 secure 检查（拒绝符号链接/非普通文件，
            // fail-closed）；回滚失败只告警，主错误仍是上面那个。即使只删掉了
            // 材料、没删掉记录，下一次加载也会按"材料缺失"把意图回滚掉。
            if let Err(rollback_error) = persistence::remove_key(directory, &key_id) {
                tracing::warn!(
                    key_id = %key_id,
                    error = %rollback_error,
                    "failed to roll back the newly persisted signing key after an interrupted rotation"
                );
            }
            if let Err(clear_error) = journal::clear_rotation(directory) {
                tracing::warn!(
                    key_id = %key_id,
                    error = %clear_error,
                    "failed to discard the rotation intent after rolling back the signing key"
                );
            }
            return Err(error);
        }
    }

    // 退役记录必须写在切换 active kid 之后。反过来写，崩溃会留下“仍在役的 key 带着
    // 退役记录”，它的保留窗口从一个过早的时刻起算，正是 Issue #298 要消除的情况。
    // 这一步失败只告警：active kid 已经前进，旧 key 已不在役，下一次加载的
    // `retirement::reconcile` 会补一条从那时起算的记录，窗口只会更长不会更短。
    if let Some(directory) = directory.as_ref()
        && let Some(retired_at) = retired_at
        && let Err(error) = retirement::stamp(directory, &previous_active_key_id, retired_at)
    {
        tracing::warn!(
            key_id = %previous_active_key_id,
            error = %error,
            "failed to record the retirement instant of the previous signing key; \
             it will be restamped on the next key directory load"
        );
    }

    // 意图记录最后清除：active kid 与退役记录都已落盘，轮换结果不会再变。清除
    // 失败只告警——记录残留会让下一次加载做一次幂等的补完，结果完全相同。
    if let Some(directory) = directory.as_ref()
        && let Err(error) = journal::clear_rotation(directory)
    {
        tracing::warn!(
            key_id = %key_id,
            error = %error,
            "failed to clear the rotation intent after the rotation completed"
        );
    }

    let published_key_count = next_state.jwks.keys.len();
    {
        let mut state = manager.write_state();
        *state = next_state;
    }

    if let Some(directory) = directory.as_ref() {
        for expired_key_id in &expired {
            if let Err(error) = persistence::remove_key(directory, expired_key_id) {
                tracing::warn!(
                    key_id = %expired_key_id,
                    error = %error,
                    "failed to collect an expired signing key"
                );
            }
        }
    }
    Ok(KeyRotation {
        key_id,
        published_key_count,
    })
}
