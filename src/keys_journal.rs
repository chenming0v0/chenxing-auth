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
//! 记录本身用 `atomic_write` 写入（临时文件 + rename），因此盘上通常只会看到完整
//! 记录或没有记录。损坏记录不能永久阻断启动，也不能猜测其中仍有哪一段可信：安全
//! 出口是丢弃整组旧材料并生成新 active key。现有 token 会失效，但可能已吊销的 key
//! 不会被恢复为 active。

use std::{fs, io::Read, path::Path};

use crate::key_storage::{atomic_write, remove_secure_file, secure_existing_file};

use super::{KeyManagerError, persistence, retirement};

/// 吊销意图记录文件。
///
/// 名字刻意落在两个既有命名空间之外：不带 `atomic_write` 的 `.chenxing-key-`
/// 前缀，因此不会被 `cleanup_stale_temporary_files` 当成中断的半成品删掉；
/// 也不带 `rs256-` 前缀，因此不会被 `discover_key_files` 当成密钥材料读进来。
const PENDING_REVOCATION_FILE: &str = "pending-revocation.record";
const MAX_PENDING_REVOCATION_BYTES: u64 = 1024;

/// 一次吊销的完整意图：吊销哪个 `kid`，完成后 active 应该是哪个 `kid`。
///
/// 吊销非 active key 时 `active_key_id` 就是当前 active，恢复路径因此不需要
/// 区分"吊销 active"和"吊销旧 key"两种情况。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingRevocation {
    revoked_key_id: String,
    active_key_id: String,
}

enum JournalRecord {
    Pending(PendingRevocation),
    Corrupt(CorruptJournal),
}

struct CorruptJournal {
    reason: CorruptionReason,
}

#[derive(Clone, Copy)]
enum CorruptionReason {
    Oversized,
    InvalidEncoding,
    InvalidRevokedKeyId,
    InvalidReplacementKeyId,
    SelfReferential,
    UnexpectedFields,
}

impl CorruptionReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Oversized => "oversized",
            Self::InvalidEncoding => "invalid_encoding",
            Self::InvalidRevokedKeyId => "invalid_revoked_key_id",
            Self::InvalidReplacementKeyId => "invalid_replacement_key_id",
            Self::SelfReferential => "self_referential",
            Self::UnexpectedFields => "unexpected_fields",
        }
    }
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
///
/// 提交点之后，调用方必须让内存快照立即放弃被吊销的 key 的签发权，即使本次
/// 收敛被瞬时 IO 失败打断——磁盘恢复只是时间问题，而内存继续签名会立刻产出
/// 其余实例验不过的 token（Issue #315）。
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

/// 读取待完成的吊销意图；内容损坏是可恢复状态，路径类型或 IO 异常仍然 fail-closed。
fn read(directory: &Path) -> Result<Option<JournalRecord>, KeyManagerError> {
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
    secure_existing_file(&path)?;
    if metadata.len() > MAX_PENDING_REVOCATION_BYTES {
        return Ok(Some(JournalRecord::Corrupt(CorruptJournal {
            reason: CorruptionReason::Oversized,
        })));
    }
    let mut contents = Vec::new();
    fs::File::open(&path)?
        .take(MAX_PENDING_REVOCATION_BYTES + 1)
        .read_to_end(&mut contents)?;
    Ok(Some(parse(&contents)))
}

/// 删除吊销记录。文件已不存在同样算成功：目标状态就是"没有待完成的吊销"。
fn clear(directory: &Path) -> Result<(), KeyManagerError> {
    match remove_secure_file(&directory.join(PENDING_REVOCATION_FILE)) {
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
/// 恢复成功时目录里必有一个不等于 revoked 的 active key 及其材料；journal 最后才
/// 清除，所以任何中断点都能从同一条记录继续，不会留下“记录已丢、active 仍缺失”的
/// 新故障窗口。
pub(super) fn recover(directory: &Path) -> Result<(), KeyManagerError> {
    let Some(record) = read(directory)? else {
        return Ok(());
    };

    match record {
        JournalRecord::Pending(pending) => recover_pending(directory, &pending)?,
        JournalRecord::Corrupt(corrupt) => recover_corrupt(directory, corrupt)?,
    }
    Ok(())
}

fn recover_pending(directory: &Path, pending: &PendingRevocation) -> Result<(), KeyManagerError> {
    let active_key_id = recoverable_active_key_id(directory)?;

    // 已有另一个可用 active 说明目录在 journal 之后已经前进，绝不能回退到记录里的
    // replacement。否则 current active 缺失、仍是 revoked 或 kid 文件本身不可用，
    // 才按 journal 选择仍存在的 replacement。
    let current_active_is_usable = match active_key_id.as_deref() {
        Some(key_id) if key_id != pending.revoked_key_id => {
            persistence::has_key_material(directory, key_id)?
        }
        _ => false,
    };

    if !current_active_is_usable {
        if persistence::has_key_material(directory, &pending.active_key_id)? {
            persistence::persist_active_key_id(directory, &pending.active_key_id)?;
            retirement::clear(directory, &pending.active_key_id)?;
        } else {
            // replacement 可能已经被裁剪。revoked 是 journal 中仍可信的事实，所以先
            // 从其他材料选择新 active（没有候选就生成），再删除 revoked。journal 在
            // 最后才清除，崩溃重试也绝不能为了可用性继续使用 revoked。
            let fallback_key_id = persistence::establish_recovery_active_key(
                directory,
                Some(pending.revoked_key_id.as_str()),
            )?;
            tracing::warn!(
                revoked_key_id = %pending.revoked_key_id,
                replacement_key_id = %pending.active_key_id,
                fallback_key_id = %fallback_key_id,
                "pending key revocation replacement is unavailable; selected a safe fallback"
            );
            persistence::remove_key(directory, &pending.revoked_key_id)?;
            clear(directory)?;
            return Ok(());
        }
    }

    persistence::remove_key(directory, &pending.revoked_key_id)?;
    clear(directory)
}

fn recover_corrupt(directory: &Path, corrupt: CorruptJournal) -> Result<(), KeyManagerError> {
    // journal 没有完整性校验，局部合法不代表该字段没被改写。保留任意旧材料都可能
    // 把真正已吊销的 key 重新发布，因此损坏记录只有一个安全出口：丢弃整个旧 keyset
    // 并立即生成新 key。日志只记录分类，不记录 journal 原文，避免把被篡改文件里的
    // 任意字节带进日志。
    persistence::discard_all_key_material(directory)?;
    let replacement_key_id = persistence::establish_recovery_active_key(directory, None)?;
    clear(directory)?;
    tracing::error!(
        reason = corrupt.reason.as_str(),
        replacement_key_id = %replacement_key_id,
        "discarded all persisted signing keys because the revocation journal was corrupt"
    );
    Ok(())
}

/// active kid 的内容损坏不应让一条可执行的 journal 永久卡死。这里只丢弃普通文件
/// 中的非法值；路径是目录或符号链接时仍由持久化层 fail-closed。
fn recoverable_active_key_id(directory: &Path) -> Result<Option<String>, KeyManagerError> {
    match persistence::declared_active_key_id(directory) {
        Ok(key_id) => Ok(key_id),
        Err(error) if active_key_id_is_unreadable(&error) => {
            tracing::warn!(
                "active signing key id is invalid while recovering a revocation; \
                 discarding the unusable pointer"
            );
            persistence::clear_active_key_id(directory)?;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn active_key_id_is_unreadable(error: &KeyManagerError) -> bool {
    matches!(error, KeyManagerError::InvalidKeyId)
        || matches!(
            error,
            KeyManagerError::Io(error) if error.kind() == std::io::ErrorKind::InvalidData
        )
}

fn parse(contents: &[u8]) -> JournalRecord {
    if contents.len() as u64 > MAX_PENDING_REVOCATION_BYTES {
        return corrupt(CorruptionReason::Oversized);
    }
    let Ok(contents) = std::str::from_utf8(contents) else {
        return corrupt(CorruptionReason::InvalidEncoding);
    };
    let mut lines = contents.lines();
    let revoked_key_id = lines.next().unwrap_or_default().trim();
    let active_key_id = lines.next().unwrap_or_default().trim();
    let has_unexpected_fields = lines.next().is_some();

    if persistence::validate_key_id(revoked_key_id).is_err() {
        return corrupt(CorruptionReason::InvalidRevokedKeyId);
    }
    if persistence::validate_key_id(active_key_id).is_err() {
        return corrupt(CorruptionReason::InvalidReplacementKeyId);
    }
    if revoked_key_id == active_key_id {
        return corrupt(CorruptionReason::SelfReferential);
    }
    if has_unexpected_fields {
        return corrupt(CorruptionReason::UnexpectedFields);
    }

    JournalRecord::Pending(PendingRevocation::new(
        revoked_key_id.to_owned(),
        active_key_id.to_owned(),
    ))
}

fn corrupt(reason: CorruptionReason) -> JournalRecord {
    JournalRecord::Corrupt(CorruptJournal { reason })
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
