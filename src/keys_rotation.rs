use std::fs;

use time::OffsetDateTime;

use crate::key_storage::{KeyStorageLock, ensure_secure_directory};

use super::{
    KeyManager, KeyManagerError, KeyRotation, build_key_state, generate_rsa_key, key_material,
    persistence, prune_materials,
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
    let (directory, retention, mut materials) = {
        let state = manager.read_state();
        (
            state.directory.clone(),
            state.retention,
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
        let (_, disk_materials) = persistence::load_materials(directory, retention, now, true)?;
        materials = disk_materials;
    }

    let (key_id, der) = generate_rsa_key()?;
    materials.insert(key_id.clone(), key_material(der.clone(), now));
    prune_materials(&key_id, &mut materials, retention, now);
    let next_state = build_key_state(directory.clone(), retention, key_id.clone(), materials)?;

    if let Some(directory) = directory.as_ref()
        && let Err(error) = persistence::persist_key(directory, &key_id, &der)
            .and_then(|_| persistence::persist_active_key_id(directory, &key_id))
    {
        let _ = fs::remove_file(directory.join(persistence::key_file_name(&key_id)));
        return Err(error);
    }

    let published_key_count = next_state.jwks.keys.len();
    {
        let mut state = manager.write_state();
        *state = next_state;
    }

    if let Some(directory) = directory.as_ref()
        && let Err(error) =
            persistence::cleanup_expired_key_files(directory, Some(&key_id), retention, now)
    {
        tracing::warn!(error = %error, "failed to collect expired signing keys");
    }
    Ok(KeyRotation {
        key_id,
        published_key_count,
    })
}
