use time::OffsetDateTime;

use crate::key_storage::{KeyStorageLock, ensure_secure_directory};

use super::{
    KeyManager, KeyManagerError, KeyRotation, activation, build_key_state, generate_rsa_key,
    journal, key_material, persistence, prune, retirement,
};

/// 轮换：先把新公钥发布进 JWKS，等到 `activate_at` 才接管签发。
///
/// 全过程持阻塞目录锁，因此与其他实例的轮换、吊销和后台同步串行化。锁必须持有到
/// 内存写入完成：后台同步用 `try_acquire`，锁被占用时会跳过本轮，所以只要写内存
/// 仍在锁内，同步就不可能用锁前读到的旧快照覆盖刚完成的轮换（Issue #257）。
///
/// 状态机（Issue #454）：
///
/// 1. 若已有未到期的 published key，本调用是幂等的——再生成一把从未签发的密钥
///    只会制造 JWKS 抖动。
/// 2. 新材料落盘并写入 `pending-activation.record` 之后，签发权仍留在旧 active。
/// 3. `activate_at` 已包含发布等待与时钟偏差围栏；`now >= activate_at` 时才切换
///    `active-rs256.kid` 并给旧 key 盖退役章。
pub(super) fn rotate_blocking_at(
    manager: &KeyManager,
    now: OffsetDateTime,
) -> Result<KeyRotation, KeyManagerError> {
    let _rotation_guard = manager
        .rotation_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (
        directory,
        retention,
        skew_allowance,
        activation_delay,
        mut previous_active_key_id,
        mut materials,
        mut pending,
    ) = {
        let state = manager.read_state();
        (
            state.directory.clone(),
            state.retention,
            state.skew_allowance,
            state.activation_delay,
            state.active_key_id.clone(),
            state.private_materials.clone(),
            state.pending.clone(),
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
        previous_active_key_id = disk_active_key_id;
        materials = disk_materials;
        pending = activation::read(directory)?;
    } else if pending.as_ref().is_some_and(|pending| pending.is_due(now)) {
        promote_in_memory(
            &mut previous_active_key_id,
            &mut materials,
            &mut pending,
            now,
        );
    }

    if let Some(pending) = pending.as_ref()
        && !pending.is_due(now)
    {
        let next_state = build_key_state(
            directory.clone(),
            retention,
            skew_allowance,
            activation_delay,
            previous_active_key_id,
            materials,
            Some(pending.clone()),
        )?;
        let published_key_count = next_state.jwks.keys.len();
        let key_id = pending.key_id.clone();
        *manager.write_state() = next_state;
        if let Some(directory) = directory.as_ref()
            && let Ok(generation) = journal::revocation_generation(directory)
        {
            manager.observe_revocation_generation(generation);
        }
        return Ok(KeyRotation {
            key_id,
            published_key_count,
        });
    }

    let (key_id, der) = generate_rsa_key()?;
    materials.insert(key_id.clone(), key_material(der.clone(), now));
    let pending = activation::PendingPublishedKey::new(
        key_id.clone(),
        previous_active_key_id.clone(),
        activation::activation_deadline(now, activation_delay, skew_allowance),
    );
    let activate_now = pending.is_due(now);
    let mut active_key_id = previous_active_key_id.clone();
    if activate_now {
        let _ = prune::mark_retired(&mut materials, &previous_active_key_id, now);
        active_key_id = key_id.clone();
    }
    let expired = prune::prune_materials(
        &active_key_id,
        &mut materials,
        retention,
        skew_allowance,
        now,
    );
    let next_state = build_key_state(
        directory.clone(),
        retention,
        skew_allowance,
        activation_delay,
        active_key_id.clone(),
        materials,
        (!activate_now).then_some(pending.clone()),
    )?;

    if let Some(directory) = directory.as_ref() {
        persist_published_rotation(
            directory,
            &key_id,
            &der,
            &previous_active_key_id,
            &pending,
            activate_now,
            now,
        )?;
    }

    let published_key_count = next_state.jwks.keys.len();
    *manager.write_state() = next_state;

    if let Some(directory) = directory.as_ref() {
        if let Ok(generation) = journal::revocation_generation(directory) {
            manager.observe_revocation_generation(generation);
        }
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

/// 窗口已到时把签发权切到 published key。调用方必须已持有轮换锁。
pub(super) fn promote_if_due(
    manager: &KeyManager,
    now: OffsetDateTime,
) -> Result<bool, KeyManagerError> {
    let (directory, retention, skew_allowance, activation_delay, active_key_id, materials, pending) = {
        let state = manager.read_state();
        (
            state.directory.clone(),
            state.retention,
            state.skew_allowance,
            state.activation_delay,
            state.active_key_id.clone(),
            state.private_materials.clone(),
            state.pending.clone(),
        )
    };
    if let Some(directory) = directory.as_ref() {
        ensure_secure_directory(directory)?;
        let _storage_lock = KeyStorageLock::acquire(directory)?;
        let previous_active = active_key_id;
        let (disk_active, disk_materials) =
            persistence::load_materials(directory, retention, skew_allowance, now, false)?;
        let pending = activation::read(directory)?;
        let activated = disk_active != previous_active;
        *manager.write_state() = build_key_state(
            Some(directory.clone()),
            retention,
            skew_allowance,
            activation_delay,
            disk_active,
            disk_materials,
            pending,
        )?;
        return Ok(activated);
    }

    let Some(pending) = pending.filter(|pending| pending.is_due(now)) else {
        return Ok(false);
    };
    let mut active_key_id = active_key_id;
    let mut materials = materials;
    let mut pending = Some(pending);
    promote_in_memory(&mut active_key_id, &mut materials, &mut pending, now);
    *manager.write_state() = build_key_state(
        None,
        retention,
        skew_allowance,
        activation_delay,
        active_key_id,
        materials,
        None,
    )?;
    Ok(true)
}

fn promote_in_memory(
    active_key_id: &mut String,
    materials: &mut std::collections::BTreeMap<String, super::KeyMaterial>,
    pending: &mut Option<activation::PendingPublishedKey>,
    now: OffsetDateTime,
) {
    let Some(published) = pending.take() else {
        return;
    };
    if !materials.contains_key(&published.key_id) {
        return;
    }
    let _ = prune::mark_retired(materials, active_key_id, now);
    *active_key_id = published.key_id;
}

fn persist_published_rotation(
    directory: &std::path::Path,
    key_id: &str,
    der: &[u8],
    previous_active_key_id: &str,
    pending: &activation::PendingPublishedKey,
    activate_now: bool,
    now: OffsetDateTime,
) -> Result<(), KeyManagerError> {
    // publish 流程只使用 activation record，不再写旧的 rotation journal。
    // 记录必须先于材料持久化：任何含新材料的崩溃状态都必然带 activate_at；
    // 只有记录、没有材料则由恢复路径安全回滚。旧二进制忽略 activation record，
    // 会把新材料当作非 active 验证 key，而不会像看到旧 journal 那样立即切签发。
    if let Err(error) = activation::record(directory, pending)
        .and_then(|_| persistence::persist_key(directory, key_id, der))
    {
        rollback_published_key(directory, key_id);
        return Err(error);
    }
    if !activate_now {
        return Ok(());
    }
    if let Err(error) = persistence::persist_active_key_id(directory, key_id) {
        // 公钥已经在 JWKS 里，签发权仍在旧 key。留下 activation 记录，
        // 下一次加载会按 `activate_at` 再切一次。
        tracing::warn!(
            key_id = %key_id,
            error = %error,
            "failed to persist the active signing key after the activation window; \
             it will be promoted on the next key directory load"
        );
        return Ok(());
    }
    if let Err(error) = activation::clear(directory) {
        tracing::warn!(
            key_id = %key_id,
            error = %error,
            "failed to clear the activation record after promoting the signing key"
        );
    }
    if let Err(error) = retirement::stamp(directory, previous_active_key_id, now) {
        tracing::warn!(
            key_id = %previous_active_key_id,
            error = %error,
            "failed to record the retirement instant of the previous signing key; \
             it will be restamped on the next key directory load"
        );
    }
    Ok(())
}

fn rollback_published_key(directory: &std::path::Path, key_id: &str) {
    if let Err(rollback_error) = persistence::remove_key(directory, key_id) {
        tracing::warn!(
            key_id = %key_id,
            error = %rollback_error,
            "failed to roll back the newly persisted signing key after an interrupted rotation"
        );
    }
    if let Err(clear_error) = activation::clear(directory) {
        tracing::warn!(
            key_id = %key_id,
            error = %clear_error,
            "failed to discard the activation record after rolling back the signing key"
        );
    }
}
