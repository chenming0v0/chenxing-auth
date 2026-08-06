use std::collections::BTreeMap;

use time::OffsetDateTime;

use crate::key_storage::{KeyStorageLock, ensure_secure_directory};

use super::{
    KeyManager, KeyManagerError, KeyMaterial, KeyRevocation, build_key_state, persistence,
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
        let (disk_active_key_id, disk_materials) =
            persistence::load_materials(directory, retention, now, false)?;
        active_key_id = disk_active_key_id;
        materials = disk_materials;
    }

    if !materials.contains_key(&key_id) {
        return Err(KeyManagerError::UnknownKeyId);
    }
    let active_key_revoked = active_key_id == key_id;
    let _ = materials.remove(&key_id);
    let next_active_key_id = if active_key_revoked {
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
        if active_key_revoked {
            persistence::persist_active_key_id(directory, &next_active_key_id)?;
        }
        if let Err(error) = persistence::remove_key(directory, &key_id) {
            if active_key_revoked
                && let Err(rollback_error) =
                    persistence::persist_active_key_id(directory, &active_key_id)
            {
                tracing::error!(
                    key_id = %key_id,
                    replacement_key_id = %next_active_key_id,
                    error = %rollback_error,
                    "failed to roll back active signing key after revocation failure"
                );
                return Err(rollback_error);
            }
            return Err(error);
        }
    }

    let published_key_count = next_state.jwks.keys.len();
    *manager.write_state() = next_state;
    Ok(KeyRevocation {
        key_id,
        active_key_id: next_active_key_id,
        published_key_count,
    })
}

fn newest_key_id(materials: &BTreeMap<String, KeyMaterial>) -> Option<String> {
    materials
        .iter()
        .max_by_key(|(_, material)| material.created_at)
        .map(|(key_id, _)| key_id.clone())
}
