//! 吊销与轮换意图的写前记录，让多文件磁盘操作成为可恢复的原子操作。
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
//! 轮换同样要改动两处磁盘事实：写入新私钥材料、把 `active-rs256.kid` 切换到
//! 新 key。崩溃发生在两步之间时会留下一个从未完成启用流程的孤儿密钥文件——
//! 它的 mtime 最新，会被吊销逻辑选为新签名密钥（Issue #318）。
//!
//! 两种操作的问题都出在"崩溃后无法判断这是操作做了一半，还是私钥被破坏"。
//! 因此这里先把意图落盘：记录存在就说明"这次操作已经决定要做"，恢复路径可以
//! 幂等地把剩下的步骤补完或回滚，既不会复活密钥，也不会留下孤儿材料，更不会
//! 把目录留在 fail-closed 状态。
//!
//! 记录本身用 `atomic_write` 写入（临时文件 + rename），因此盘上通常只会看到完整
//! 记录或没有记录。损坏记录不能永久阻断启动，也不能猜测其中仍有哪一段可信：安全
//! 出口是丢弃整组旧材料并生成新 active key。现有 token 会失效，但可能已吊销的 key
//! 不会被恢复为 active。

use std::path::Path;

use crate::key_storage::{atomic_write, read_secure_file_limited, remove_secure_file};

use super::{KeyManagerError, activation, persistence, retirement};

/// 吊销意图记录文件。
///
/// 名字刻意落在既有命名空间之外：不带 `atomic_write` 的临时文件前缀
/// （`.chenxing-key-` / `.chenxing-secret-`），因此不会被
/// `cleanup_stale_temporary_files` 当成中断的半成品删掉；也不带 `rs256-`
/// 前缀，因此不会被 `discover_key_files` 当成密钥材料读进来。
const PENDING_REVOCATION_FILE: &str = "pending-revocation.record";
/// 轮换意图记录文件，命名约束与吊销记录相同（Issue #318）。
const PENDING_ROTATION_FILE: &str = "pending-rotation.record";
const MAX_PENDING_RECORD_BYTES: u64 = 1024;

/// 一次吊销的完整意图：吊销哪个 `kid`，完成后 active 应该是哪个 `kid`。
///
/// 吊销非 active key 时 `active_key_id` 就是当前 active，恢复路径因此不需要
/// 区分"吊销 active"和"吊销旧 key"两种情况。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingRevocation {
    revoked_key_id: String,
    active_key_id: String,
}

/// 一次轮换的完整意图：新 key 是哪个，轮换前 active 是哪个（Issue #318）。
///
/// `previous_key_id` 让记录自足：恢复路径不需要读回任何其他文件就能判断"kid
/// 是否已切换、切换目标是谁"，并据此补完或回滚；同时它参与自引用校验
/// （`new == previous` 只能是篡改）。旧 key 的退役记录不在这里写，由加载路径
/// 的 `retirement::reconcile` 统一补齐。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingRotation {
    new_key_id: String,
    previous_key_id: String,
}

enum JournalRecord {
    Pending(PendingRevocation),
    Corrupt(CorruptJournal),
}

enum RotationJournalRecord {
    Pending(PendingRotation),
    Corrupt(CorruptJournal),
}

struct CorruptJournal {
    reason: CorruptionReason,
}

#[derive(Clone, Copy)]
enum CorruptionReason {
    Oversized,
    InvalidEncoding,
    InvalidFirstKeyId,
    InvalidSecondKeyId,
    SelfReferential,
    UnexpectedFields,
}

impl CorruptionReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Oversized => "oversized",
            Self::InvalidEncoding => "invalid_encoding",
            Self::InvalidFirstKeyId => "invalid_first_key_id",
            Self::InvalidSecondKeyId => "invalid_second_key_id",
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

impl PendingRotation {
    pub(super) fn new(new_key_id: String, previous_key_id: String) -> Self {
        Self {
            new_key_id,
            previous_key_id,
        }
    }
}

/// 把吊销意图落盘。返回成功即表示这次吊销已提交，崩溃后恢复路径会把它做完。
///
/// 提交点之后，调用方必须让内存快照立即放弃被吊销的 key 的签发权，即使本次
/// 收敛被瞬时 IO 失败打断——磁盘恢复只是时间问题，而内存继续签名会立刻产出
/// 其余实例验不过的 token（Issue #315）。
pub(super) fn record(directory: &Path, pending: &PendingRevocation) -> Result<(), KeyManagerError> {
    validate_pair(&pending.revoked_key_id, &pending.active_key_id)?;
    let contents = format!("{}\n{}\n", pending.revoked_key_id, pending.active_key_id);
    atomic_write(
        &directory.join(PENDING_REVOCATION_FILE),
        contents.as_bytes(),
        true,
    )?;
    Ok(())
}

/// 把轮换意图落盘。返回成功即表示这次轮换已提交：崩溃后加载路径会把它补完或
/// 回滚，不会留下从未进入 JWKS 的孤儿私钥（Issue #318）。
pub(super) fn record_rotation(
    directory: &Path,
    pending: &PendingRotation,
) -> Result<(), KeyManagerError> {
    validate_pair(&pending.new_key_id, &pending.previous_key_id)?;
    let contents = format!("{}\n{}\n", pending.new_key_id, pending.previous_key_id);
    atomic_write(
        &directory.join(PENDING_ROTATION_FILE),
        contents.as_bytes(),
        true,
    )?;
    Ok(())
}

/// 读取待完成的吊销意图；内容损坏是可恢复状态，路径类型或 IO 异常仍然 fail-closed。
fn read(directory: &Path) -> Result<Option<JournalRecord>, KeyManagerError> {
    read_record(directory, PENDING_REVOCATION_FILE, parse, || {
        corrupt(CorruptionReason::Oversized)
    })
}

/// 读取待完成的轮换意图；内容损坏是可恢复状态，路径类型或 IO 异常仍然 fail-closed。
fn read_rotation(directory: &Path) -> Result<Option<RotationJournalRecord>, KeyManagerError> {
    read_record(directory, PENDING_ROTATION_FILE, parse_rotation, || {
        corrupt_rotation(CorruptionReason::Oversized)
    })
}

/// 读取一份两行 id 记录的通用实现：文件不存在返回 `None`，内容过大直接判损坏，
/// 否则读出原始字节交给调用方的解析函数。
fn read_record<T>(
    directory: &Path,
    file_name: &str,
    parse: impl FnOnce(&[u8]) -> T,
    oversized: impl FnOnce() -> T,
) -> Result<Option<T>, KeyManagerError> {
    let path = directory.join(file_name);
    let contents = match read_secure_file_limited(&path, MAX_PENDING_RECORD_BYTES) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if contents.len() as u64 > MAX_PENDING_RECORD_BYTES {
        return Ok(Some(oversized()));
    }
    Ok(Some(parse(&contents)))
}

/// 删除吊销记录。文件已不存在同样算成功：目标状态就是"没有待完成的吊销"。
fn clear(directory: &Path) -> Result<(), KeyManagerError> {
    clear_record(directory, PENDING_REVOCATION_FILE)
}

/// 删除轮换意图记录。文件已不存在同样算成功。
pub(super) fn clear_rotation(directory: &Path) -> Result<(), KeyManagerError> {
    clear_record(directory, PENDING_ROTATION_FILE)
}

fn clear_record(directory: &Path, file_name: &str) -> Result<(), KeyManagerError> {
    match remove_secure_file(&directory.join(file_name)) {
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
/// 清除，所以任何中断点都能从同一条记录继续，不会留下"记录已丢、active 仍缺失"的
/// 新故障窗口。
pub(super) fn recover(directory: &Path, now: time::OffsetDateTime) -> Result<(), KeyManagerError> {
    recover_rotation(directory)?;
    let Some(record) = read(directory)? else {
        activation::recover(directory, now)?;
        return Ok(());
    };

    match record {
        JournalRecord::Pending(pending) => recover_pending(directory, &pending)?,
        JournalRecord::Corrupt(corrupt) => recover_corrupt(directory, corrupt)?,
    }
    // 吊销恢复可能已经删掉 pending 材料或把它提升为 active，再收敛激活记录。
    activation::recover(directory, now)?;
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

/// 幂等地把待完成的轮换收敛：要么补完切换，要么回滚意图（Issue #318）。
///
/// 轮换的意图在写任何私钥材料之前落盘，因此恢复不需要猜测盘上多出来的材料是
/// 什么：active kid 已指向新 key 说明切换完成，直接清除记录；kid 未切换而新材料
/// 在盘上说明崩溃发生在写 key 与写 kid 之间，补完切换；新材料不在盘上说明崩溃
/// 发生在写材料之前，轮换从未生效，回滚意图即可（运维重试一次轮换）。
///
/// 旧 key 的退役记录不在这里补：加载路径的 `retirement::reconcile` 会为记录缺失
/// 的非 active key 统一盖章，避免恢复路径与 reconcile 各写一份。
fn recover_rotation(directory: &Path) -> Result<(), KeyManagerError> {
    let Some(record) = read_rotation(directory)? else {
        return Ok(());
    };
    match record {
        RotationJournalRecord::Pending(pending) => {
            let active_key_id = recoverable_active_key_id(directory)?;
            let switch_completed = active_key_id.as_deref() == Some(pending.new_key_id.as_str());
            if !switch_completed {
                if persistence::has_key_material(directory, &pending.new_key_id)? {
                    // 激活记录在时，签发切换由 `activation::recover` 按 `activate_at`
                    // 决定。这里再切一次会跳过 JWKS 传播窗口（Issue #454）。
                    let activation = match activation::read(directory) {
                        Ok(published) => published,
                        Err(KeyManagerError::InvalidKeyId) => None,
                        Err(error) => return Err(error),
                    };
                    if activation.is_none() {
                        persistence::persist_active_key_id(directory, &pending.new_key_id)?;
                    }
                } else {
                    tracing::warn!(
                        new_key_id = %pending.new_key_id,
                        "an interrupted rotation never took effect; its intent is discarded"
                    );
                }
            }
            clear_rotation(directory)?;
        }
        RotationJournalRecord::Corrupt(corrupt) => recover_corrupt(directory, corrupt)?,
    }
    Ok(())
}

fn recover_corrupt(directory: &Path, corrupt: CorruptJournal) -> Result<(), KeyManagerError> {
    // journal 没有完整性校验，局部合法不代表该字段没被改写。保留任意旧材料都可能
    // 把真正已吊销的 key 重新发布，因此损坏记录只有一个安全出口：丢弃整个旧 keyset
    // 并立即生成新 key。日志只记录分类，不记录 journal 原文，避免把被篡改文件里的
    // 任意字节带进日志。两份记录文件（吊销与轮换）都清除，任何一份残留都会让
    // 下一次加载再次进入这条路径。
    persistence::discard_all_key_material(directory)?;
    let replacement_key_id = persistence::establish_recovery_active_key(directory, None)?;
    clear(directory)?;
    clear_rotation(directory)?;
    tracing::error!(
        reason = corrupt.reason.as_str(),
        replacement_key_id = %replacement_key_id,
        "discarded all persisted signing keys because a key operation journal was corrupt"
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
                "active signing key id is invalid while recovering a key operation; \
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

/// 吊销记录的两行格式：`{revoked}\n{active}\n`。
fn parse(contents: &[u8]) -> JournalRecord {
    match parse_two_key_ids(contents) {
        Ok((revoked_key_id, active_key_id)) => {
            JournalRecord::Pending(PendingRevocation::new(revoked_key_id, active_key_id))
        }
        Err(reason) => corrupt(reason),
    }
}

/// 轮换记录的两行格式：`{new}\n{previous}\n`。
fn parse_rotation(contents: &[u8]) -> RotationJournalRecord {
    match parse_two_key_ids(contents) {
        Ok((new_key_id, previous_key_id)) => {
            RotationJournalRecord::Pending(PendingRotation::new(new_key_id, previous_key_id))
        }
        Err(reason) => corrupt_rotation(reason),
    }
}

/// 两行 key id 记录的通用解析与校验。
///
/// 第一行 / 第二行分别对应两个 key id（吊销：revoked / active；轮换：new /
/// previous）。任一行无法识别都不能猜哪个 key 被涉及：交给调用方按损坏处理。
fn parse_two_key_ids(contents: &[u8]) -> Result<(String, String), CorruptionReason> {
    if contents.len() as u64 > MAX_PENDING_RECORD_BYTES {
        return Err(CorruptionReason::Oversized);
    }
    let Ok(contents) = std::str::from_utf8(contents) else {
        return Err(CorruptionReason::InvalidEncoding);
    };
    let mut lines = contents.lines();
    let first_key_id = lines.next().unwrap_or_default().trim();
    let second_key_id = lines.next().unwrap_or_default().trim();
    let has_unexpected_fields = lines.next().is_some();

    if persistence::validate_key_id(first_key_id).is_err() {
        return Err(CorruptionReason::InvalidFirstKeyId);
    }
    if persistence::validate_key_id(second_key_id).is_err() {
        return Err(CorruptionReason::InvalidSecondKeyId);
    }
    if first_key_id == second_key_id {
        return Err(CorruptionReason::SelfReferential);
    }
    if has_unexpected_fields {
        return Err(CorruptionReason::UnexpectedFields);
    }

    Ok((first_key_id.to_owned(), second_key_id.to_owned()))
}

fn corrupt(reason: CorruptionReason) -> JournalRecord {
    JournalRecord::Corrupt(CorruptJournal { reason })
}

fn corrupt_rotation(reason: CorruptionReason) -> RotationJournalRecord {
    RotationJournalRecord::Corrupt(CorruptJournal { reason })
}

/// 记录内容的合法性检查，读写两侧共用。
///
/// 两个 key id 相同会让恢复路径先把 kid 指向某个 key、再删掉它自己的材料，
/// 正好造出 fail-closed 目录。吊销与轮换永远不会写出这种记录（替代 kid 取自
/// 移除后剩下的材料，新 key 是刚生成的），所以读到它只能是外部篡改或文件损坏。
fn validate_pair(first_key_id: &str, second_key_id: &str) -> Result<(), KeyManagerError> {
    persistence::validate_key_id(first_key_id)?;
    persistence::validate_key_id(second_key_id)?;
    if first_key_id == second_key_id {
        return Err(KeyManagerError::InvalidKeyId);
    }
    Ok(())
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
