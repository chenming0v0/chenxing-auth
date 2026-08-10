//! 吊销意图的写前记录，让"换 active kid"与"删除旧私钥材料"成为一次可恢复的操作。
//!
//! 吊销 active key 必须同时改动两处磁盘事实：`active-rs256.kid` 指向替代密钥，
//! 以及被吊销的私钥材料从目录里消失。这两步无法在一次系统调用里完成，中间任何
//! 崩溃都会留下半成品：
//!
//! - 先写 kid 再删材料：崩溃在中间时，被吊销的材料仍在盘上。重启后
//!   `discover_key_files` 会把它读回来并重新发布进 JWKS——已吊销的密钥复活，
//!   用它签发的令牌重新可验证。这是 Issue #284。
//! - 先删材料再写 kid：崩溃在中间时，kid 指向已被删除的材料，`load_materials`
//!   按 Issue #264 的约定 fail-closed，服务再也起不来，只能人工修盘。
//!
//! 两种顺序的问题都出在"崩溃后无法判断这是吊销做了一半，还是私钥被破坏"。
//! 因此这里先把意图落盘：记录存在就说明"这次吊销已经决定要做"，恢复路径可以
//! 幂等地把剩下的步骤补完，既不会复活密钥，也不会把目录留在 fail-closed 状态。
//!
//! 记录本身用 `atomic_write` 写入（临时文件 + rename），因此盘上只会看到完整
//! 记录或没有记录；读到内容但解析失败属于外部篡改，一律 fail-closed。

use std::{fs, path::Path};

use crate::key_storage::atomic_write;

use super::{KeyManagerError, persistence};

/// 吊销意图记录文件。
///
/// 名字刻意落在两个既有命名空间之外：不带 `atomic_write` 的 `.chenxing-key-`
/// 前缀，因此不会被 `cleanup_stale_temporary_files` 当成中断的半成品删掉；
/// 也不带 `rs256-` 前缀，因此不会被 `discover_key_files` 当成密钥材料读进来。
const PENDING_REVOCATION_FILE: &str = "pending-revocation.record";

/// 一次吊销的完整意图：吊销哪个 `kid`，完成后 active 应该是哪个 `kid`。
///
/// 吊销非 active key 时 `active_key_id` 就是当前 active，恢复路径因此不需要
/// 区分"吊销 active"和"吊销旧 key"两种情况。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingRevocation {
    revoked_key_id: String,
    active_key_id: String,
}

impl PendingRevocation {
    pub(super) fn new(revoked_key_id: String, active_key_id: String) -> Self {
        Self {
            revoked_key_id,
            active_key_id,
        }
    }
}

/// 把吊销意图落盘。返回成功即表示这次吊销已提交，崩溃后恢复路径会把它做完。
pub(super) fn record(directory: &Path, pending: &PendingRevocation) -> Result<(), KeyManagerError> {
    validate(pending)?;
    let contents = format!("{}\n{}\n", pending.revoked_key_id, pending.active_key_id);
    atomic_write(
        &directory.join(PENDING_REVOCATION_FILE),
        contents.as_bytes(),
        true,
    )?;
    Ok(())
}

/// 读取待完成的吊销意图；没有记录时返回 `None`。
fn read(directory: &Path) -> Result<Option<PendingRevocation>, KeyManagerError> {
    let path = directory.join(PENDING_REVOCATION_FILE);
    let metadata = match fs::symlink_metadata(&path) {
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
    let contents = fs::read_to_string(&path)?;
    let mut lines = contents.lines();
    let revoked_key_id = lines.next().unwrap_or_default().trim().to_owned();
    let active_key_id = lines.next().unwrap_or_default().trim().to_owned();
    let pending = PendingRevocation::new(revoked_key_id, active_key_id);
    validate(&pending)?;
    Ok(Some(pending))
}

/// 删除吊销记录。文件已不存在同样算成功：目标状态就是"没有待完成的吊销"。
fn clear(directory: &Path) -> Result<(), KeyManagerError> {
    match fs::remove_file(directory.join(PENDING_REVOCATION_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// 幂等地把待完成的吊销做完。
///
/// 正常吊销和崩溃恢复走的是同一条路径：`revoke` 先写记录再调用本函数，重启时
/// `load_materials` 也调用本函数。因此"顺序正确"这件事只在这里实现一次，不存在
/// 第二份需要跟着维护的补偿逻辑。
///
/// 步骤顺序固定为：先把 active kid 指向替代密钥，再删除被吊销的材料，最后清除
/// 记录。任何一步失败都保留记录，下一次加载会重新走同样的步骤。
pub(super) fn recover(directory: &Path) -> Result<(), KeyManagerError> {
    let Some(pending) = read(directory)? else {
        return Ok(());
    };

    // active kid 仍指向被吊销的 key，才需要改写它。若已经指向别处（吊销非 active
    // key，或吊销完成后又发生过轮换），改写会把 active 退回一个更旧的 kid。
    if persistence::declared_active_key_id(directory)?.as_deref() == Some(&pending.revoked_key_id) {
        // 替代材料必须真的在盘上：否则改写 kid 会造出"kid 指向缺失材料"的目录，
        // 把一次可恢复的吊销升级成 Issue #264 的 fail-closed 故障。
        if !persistence::has_key_material(directory, &pending.active_key_id)? {
            tracing::error!(
                revoked_key_id = %pending.revoked_key_id,
                replacement_key_id = %pending.active_key_id,
                "pending revocation names a replacement signing key whose material is missing; \
                 refusing to complete the revocation"
            );
            return Err(KeyManagerError::MissingActiveKeyMaterial);
        }
        persistence::persist_active_key_id(directory, &pending.active_key_id)?;
    }

    persistence::remove_key(directory, &pending.revoked_key_id)?;
    clear(directory)?;
    Ok(())
}

/// 记录内容的合法性检查，读写两侧共用。
///
/// `revoked == active` 会让恢复路径先把 kid 指向某个 key、再删掉它自己的材料，
/// 正好造出 fail-closed 目录。吊销永远不会写出这种记录（替代 kid 取自移除后
/// 剩下的材料），所以读到它只能是外部篡改或文件损坏。
fn validate(pending: &PendingRevocation) -> Result<(), KeyManagerError> {
    persistence::validate_key_id(&pending.revoked_key_id)?;
    persistence::validate_key_id(&pending.active_key_id)?;
    if pending.revoked_key_id == pending.active_key_id {
        return Err(KeyManagerError::InvalidKeyId);
    }
    Ok(())
}

#[cfg(test)]
#[path = "keys_journal_tests.rs"]
mod tests;
