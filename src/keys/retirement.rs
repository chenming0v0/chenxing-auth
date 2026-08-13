//! 退役时刻记录：让“旧公钥还要保留多久”从退役那一刻起算。
//!
//! 保留窗口的正确起点是密钥停止签发的时刻，不是它被创建的时刻（Issue #298）。
//! 一个 key 可能在役数天甚至数周，轮换那一刻它才从“签发 + 验证”降级为“只验证”。
//! 用创建时刻起算，长期在役的 key 会在轮换的同一瞬间就越过窗口：它在最后一刻
//! 签发、尚未到 `exp` 的令牌立刻验不过，公钥同时从 JWKS 和磁盘上消失。
//!
//! 创建时刻可以从文件 mtime 读出来，退役时刻没有天然载体，因此每个已退役的 key
//! 在目录里多一个同名 sidecar 记录。名字刻意落在两个既有命名空间之外：不带
//! `atomic_write` 的 `.chenxing-key-` 前缀，因此不会被 `cleanup_stale_temporary_files`
//! 当成中断的半成品删掉；后缀不是 `.pkcs1.der`，因此不会被 `discover_key_files`
//! 当成密钥材料读进来。
//!
//! 不变量（由 `reconcile` 在目录锁内双向维持）：active key 没有记录，其余每个 key
//! 都有记录。两个方向都会被修正，因此崩溃遗留的半成品、以及升级前就存在的历史
//! 目录都会自愈，不需要一次性迁移脚本。

use std::{collections::BTreeMap, fs, path::Path};

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::key_storage::{atomic_write, secure_existing_file};

use super::{KeyManagerError, KeyMaterial, persistence};

/// 退役记录的后缀。前缀沿用密钥材料的 `rs256-`，因此同一个 `kid` 的材料与记录在
/// 目录列表里相邻，运维排查时不需要在两套命名之间做心算。
const RETIREMENT_FILE_SUFFIX: &str = ".retired";

pub(super) fn retirement_file_name(key_id: &str) -> String {
    format!(
        "{}{key_id}{RETIREMENT_FILE_SUFFIX}",
        persistence::KEY_FILE_PREFIX
    )
}

/// 读取某个 `kid` 的退役时刻；没有记录时返回 `None`。
///
/// 记录损坏或无法解析时按“没有记录”处理并告警，而不是 fail-closed 让服务起不来。
/// 这个方向是安全的：缺少记录只会让 `reconcile` 重新盖一个更晚的退役时刻，从而
/// 多留一个保留窗口；反过来把无法解析当成致命错误，则会因为一个非凭据的元数据
/// 文件损坏而拒绝启动整个认证服务。
///
/// `pub(super)` 供恢复路径（`establish_recovery_active_key`）做"最近在役"排序：
/// 那是替代者选择的唯一可信依据，不能退回文件 mtime（Issue #318）。
pub(super) fn read_retired_at(
    directory: &Path,
    key_id: &str,
) -> Result<Option<OffsetDateTime>, KeyManagerError> {
    let path = directory.join(retirement_file_name(key_id));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    // 非普通文件说明目录被篡改：与密钥材料同样 fail-closed，不能静默当成“没有记录”
    // 之后往这个路径上写。
    if !metadata.is_file() {
        return Err(KeyManagerError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid secure storage path",
        )));
    }
    secure_existing_file(&path)?;
    let contents = fs::read_to_string(&path)?;
    match OffsetDateTime::parse(contents.trim(), &Rfc3339) {
        Ok(retired_at) => Ok(Some(retired_at)),
        Err(_) => {
            tracing::warn!(
                key_id = %key_id,
                "signing key retirement record is unreadable; \
                 restamping it grants the key another full retention window"
            );
            Ok(None)
        }
    }
}

/// 写入退役时刻。已存在同样内容时是幂等的。
pub(super) fn stamp(
    directory: &Path,
    key_id: &str,
    retired_at: OffsetDateTime,
) -> Result<(), KeyManagerError> {
    persistence::validate_key_id(key_id)?;
    let contents = retired_at
        .format(&Rfc3339)
        .map_err(|_| KeyManagerError::InvalidKeyId)?;
    atomic_write(
        &directory.join(retirement_file_name(key_id)),
        format!("{contents}\n").as_bytes(),
        true,
    )?;
    Ok(())
}

/// 删除退役记录。记录已不存在同样算成功：目标状态就是“这个 key 没有退役记录”。
pub(super) fn clear(directory: &Path, key_id: &str) -> Result<(), KeyManagerError> {
    persistence::validate_key_id(key_id)?;
    match fs::remove_file(directory.join(retirement_file_name(key_id))) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// 从盘上补齐一份材料快照的退役时刻。
pub(super) fn load_into(
    directory: &Path,
    key_id: &str,
    material: &mut KeyMaterial,
) -> Result<(), KeyManagerError> {
    material.retired_at = read_retired_at(directory, key_id)?;
    Ok(())
}

/// 在目录锁内把“active key 没有记录，其余都有记录”这条不变量落实到内存与磁盘。
///
/// 两个方向都必须修正：
///
/// - 非 active 却没有记录：升级前就存在的历史目录，或轮换写完 active kid 之后、
///   写记录之前崩溃。就地补一条从 `now` 起算的记录。宁可多给一个完整窗口，也不能
///   凭空推断一个更早的退役时刻——那正是 Issue #298 误删仍需验证公钥的原因。
/// - active 却带着记录：吊销把 active 退回一个更旧的 key，或崩溃遗留。必须清掉，
///   否则这个 key 下次退役时会沿用一个过早的起点，同一个 bug 换个入口复现。
pub(super) fn reconcile(
    directory: &Path,
    active_key_id: &str,
    materials: &mut BTreeMap<String, KeyMaterial>,
    now: OffsetDateTime,
) -> Result<(), KeyManagerError> {
    for (key_id, material) in materials.iter_mut() {
        if key_id == active_key_id {
            if material.retired_at.take().is_some() {
                clear(directory, key_id)?;
            }
            continue;
        }
        if material.retired_at.is_none() {
            stamp(directory, key_id, now)?;
            material.retired_at = Some(now);
        }
    }
    remove_orphaned_records(directory, materials)
}

/// 清理没有对应私钥材料的记录。
///
/// 吊销与过期回收都会先删材料再删记录，中间崩溃会留下孤立记录。留着它并不影响
/// 安全判断（没有材料就不会被发布），但会让目录随时间单调增长，也会让运维误以为
/// 某个 `kid` 仍在保留窗口内。
fn remove_orphaned_records(
    directory: &Path,
    materials: &BTreeMap<String, KeyMaterial>,
) -> Result<(), KeyManagerError> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(key_id) = file_name
            .strip_prefix(persistence::KEY_FILE_PREFIX)
            .and_then(|value| value.strip_suffix(RETIREMENT_FILE_SUFFIX))
        else {
            continue;
        };
        if materials.contains_key(key_id) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
