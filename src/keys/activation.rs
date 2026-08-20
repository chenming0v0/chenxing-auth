//! 已发布、尚未签发的轮换密钥（Issue #454）。
//!
//! 轮换拆成两个持久化阶段：先把新公钥写入 JWKS（published），等到记录里的
//! `activate_at` 之后才把签发权切过去（active）。截止时刻已经包含配置的跨实例
//! 时钟偏差围栏，并写在独立文件里；重启和多实例恢复看的是同一份时间，而不是
//! 进程内 sleep 或各自重新解释当前配置。
//!
//! 记录文件刻意不复用 `pending-rotation.record`：那份 journal 仍只负责
//! “材料落盘 / 回滚”的崩溃窗口，格式保持两行。旧二进制不认识本文件，
//! 回滚时会忽略它并继续用旧 active 签发，不会把 3 行记录判成损坏后清空
//! 整个 keyset。

use std::{path::Path, time::Duration};

use time::{
    Duration as TimeDuration, OffsetDateTime, PlainDateTime,
    format_description::well_known::Rfc3339,
};

use crate::key_storage::{atomic_write, read_secure_file_limited, remove_secure_file};

use super::{KeyManager, KeyManagerError, persistence};

/// JWKS 公开缓存的 `max-age`（秒）。传播窗口下界必须覆盖它，否则 RP 仍拿着
/// 旧 JWKS 时新私钥已经开始签发。
pub const JWKS_CACHE_MAX_AGE_SECONDS: u64 = 60;

/// 默认激活等待：JWKS `max-age` + 一次跨实例同步周期。
pub const DEFAULT_KEY_ACTIVATION_DELAY_SECONDS: u64 =
    JWKS_CACHE_MAX_AGE_SECONDS + super::DEFAULT_KEY_SYNC_INTERVAL.as_secs();

/// 激活等待上界（秒）。再长只会把轮换本身拖成拒绝服务，不能修复缓存。
pub const MAX_KEY_ACTIVATION_DELAY_SECONDS: u64 = 300;

const PENDING_ACTIVATION_FILE: &str = "pending-activation.record";
const MAX_PENDING_RECORD_BYTES: u64 = 1024;

/// 一份已发布、等待 `activate_at` 才接管签发的密钥。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingPublishedKey {
    pub key_id: String,
    pub previous_key_id: String,
    pub activate_at: OffsetDateTime,
}

impl PendingPublishedKey {
    pub(super) fn new(
        key_id: String,
        previous_key_id: String,
        activate_at: OffsetDateTime,
    ) -> Self {
        Self {
            key_id,
            previous_key_id,
            activate_at,
        }
    }

    pub(super) fn is_due(&self, now: OffsetDateTime) -> bool {
        now >= self.activate_at
    }

    /// 缺 active 指针时：(preferred, excluded)。
    ///
    /// 窗口未到：保住上一把真正在役的 key，排除本 pending key，避免重启把未来
    /// 密钥提前写成 active（Issue #655）。窗口已到：本 key 就是该激活的对象。
    pub(super) fn recovery_choice(&self, now: OffsetDateTime) -> (Option<&str>, Option<&str>) {
        if self.is_due(now) {
            (Some(self.key_id.as_str()), None)
        } else {
            (
                Some(self.previous_key_id.as_str()),
                Some(self.key_id.as_str()),
            )
        }
    }
}

/// `now + delay`；无法表示的 delay 取时间上界，按“永不到期”安全失败。
pub(super) fn activate_at(now: OffsetDateTime, delay: Duration) -> OffsetDateTime {
    TimeDuration::try_from(delay)
        .ok()
        .and_then(|delay| now.checked_add(delay))
        .unwrap_or_else(|| PlainDateTime::MAX.assume_utc())
}

/// 持久化的安全激活截止：JWKS 传播等待加跨实例最大时钟偏差。
///
/// 偏慢的发布实例写入截止、偏快的激活实例读取截止时，`skew_allowance` 不能消耗
/// `activation_delay` 的任何一秒。截止一旦落盘就不受之后的配置变更影响。
pub(super) fn activation_deadline(
    now: OffsetDateTime,
    activation_delay: Duration,
    skew_allowance: Duration,
) -> OffsetDateTime {
    activate_at(now, activation_delay.saturating_add(skew_allowance))
}

/// 把“已发布、待激活”落盘。返回成功即表示新公钥必须进入 JWKS，签发权仍留在旧 key。
pub(super) fn record(
    directory: &Path,
    pending: &PendingPublishedKey,
) -> Result<(), KeyManagerError> {
    persistence::validate_key_id(&pending.key_id)?;
    persistence::validate_key_id(&pending.previous_key_id)?;
    if pending.key_id == pending.previous_key_id {
        return Err(KeyManagerError::InvalidKeyId);
    }
    let activate_at = pending
        .activate_at
        .format(&Rfc3339)
        .map_err(|_| KeyManagerError::InvalidKeyId)?;
    let contents = format!(
        "{}\n{}\n{activate_at}\n",
        pending.key_id, pending.previous_key_id
    );
    atomic_write(
        &directory.join(PENDING_ACTIVATION_FILE),
        contents.as_bytes(),
        true,
    )?;
    Ok(())
}

pub(super) fn read(directory: &Path) -> Result<Option<PendingPublishedKey>, KeyManagerError> {
    let path = directory.join(PENDING_ACTIVATION_FILE);
    let contents = match read_secure_file_limited(&path, MAX_PENDING_RECORD_BYTES) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if contents.len() as u64 > MAX_PENDING_RECORD_BYTES {
        return Err(KeyManagerError::InvalidKeyId);
    }
    parse(&contents)
}

pub(super) fn clear(directory: &Path) -> Result<(), KeyManagerError> {
    match remove_secure_file(&directory.join(PENDING_ACTIVATION_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// 窗口已到就把签发权切到已发布的 key；未到则原样留下记录。
///
/// 材料缺失时丢弃记录：没有公钥可发布，签发权绝不能切过去。
/// 窗口未到且 active 指针丢失（或内容非法）时，把上一把真正在役的 key 写回去，
/// 绝不能让“选 newest”把 pending 密钥提前激活（Issue #655）。
pub(super) fn recover(directory: &Path, now: OffsetDateTime) -> Result<(), KeyManagerError> {
    let pending = match read(directory) {
        Ok(Some(pending)) => pending,
        Ok(None) => return Ok(()),
        Err(KeyManagerError::InvalidKeyId) => {
            tracing::error!(
                "discarding a corrupt pending-activation record; \
                 the current active signing key is left unchanged"
            );
            clear(directory)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };

    if !persistence::has_key_material(directory, &pending.key_id)? {
        tracing::warn!(
            key_id = %pending.key_id,
            "pending published signing key material is missing; discarding the activation record"
        );
        return clear(directory);
    }
    if pending.is_due(now) {
        persistence::persist_active_key_id(directory, &pending.key_id)?;
        return clear(directory);
    }
    if active_pointer_missing(directory)?
        && persistence::has_key_material(directory, &pending.previous_key_id)?
    {
        tracing::warn!(
            previous_key_id = %pending.previous_key_id,
            "active key id file is missing during a pending activation; \
             restoring the last active signing key"
        );
        persistence::persist_active_key_id(directory, &pending.previous_key_id)?;
    }
    Ok(())
}

fn active_pointer_missing(directory: &Path) -> Result<bool, KeyManagerError> {
    match persistence::declared_active_key_id(directory) {
        Ok(None) => Ok(true),
        Ok(Some(_)) => Ok(false),
        Err(KeyManagerError::InvalidKeyId) => Ok(true),
        Err(error) => Err(error),
    }
}

fn parse(contents: &[u8]) -> Result<Option<PendingPublishedKey>, KeyManagerError> {
    let Ok(contents) = std::str::from_utf8(contents) else {
        return Err(KeyManagerError::InvalidKeyId);
    };
    let mut lines = contents.lines();
    let key_id = lines.next().unwrap_or_default().trim();
    let previous_key_id = lines.next().unwrap_or_default().trim();
    let activate_at = lines.next().unwrap_or_default().trim();
    if lines.next().is_some() {
        return Err(KeyManagerError::InvalidKeyId);
    }
    persistence::validate_key_id(key_id)?;
    persistence::validate_key_id(previous_key_id)?;
    if key_id == previous_key_id {
        return Err(KeyManagerError::InvalidKeyId);
    }
    let activate_at =
        OffsetDateTime::parse(activate_at, &Rfc3339).map_err(|_| KeyManagerError::InvalidKeyId)?;
    Ok(Some(PendingPublishedKey::new(
        key_id.to_owned(),
        previous_key_id.to_owned(),
        activate_at,
    )))
}

impl KeyManager {
    /// 当前已发布、尚未接管签发的 `kid`。没有 pending 轮换时返回 `None`。
    pub fn published_key_id(&self) -> Option<String> {
        self.read_state()
            .pending
            .as_ref()
            .map(|pending| pending.key_id.clone())
    }

    /// 若 pending 轮换的 `activate_at` 已到，把签发权切过去。
    ///
    /// 磁盘模式走同一条加载恢复路径，因此重启、第二实例和本调用看到的是同一份
    /// 截止时刻。返回 `true` 表示本次确实完成了激活。
    pub async fn activate_published_at(
        &self,
        now: OffsetDateTime,
    ) -> Result<bool, KeyManagerError> {
        let manager = self.clone();
        tokio::task::spawn_blocking(move || activate_published_blocking(&manager, now))
            .await
            .map_err(|_| KeyManagerError::KeyWorker)?
    }
}

pub(super) fn activate_published_blocking(
    manager: &KeyManager,
    now: OffsetDateTime,
) -> Result<bool, KeyManagerError> {
    let _rotation_guard = manager
        .rotation_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    super::rotation::promote_if_due(manager, now)
}

#[cfg(test)]
#[path = "activation_tests.rs"]
mod tests;
