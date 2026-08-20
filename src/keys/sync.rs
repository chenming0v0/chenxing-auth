//! 共享密钥目录与内存快照之间的后台同步边界。
//!
//! 请求热路径（签发、验证、JWKS）只读 `KeyManager` 的内存快照，磁盘一致性全部
//! 收敛到这里：
//!
//! - 启动加载：`KeyManager::load_or_generate*` 用阻塞锁独占读取一次，缺失时生成。
//! - 轮换 / 吊销：在 `spawn_blocking` 里持阻塞目录锁写入，并同步更新内存快照。
//! - 后台同步：本模块的 worker 周期性（或收到热路径提示后）用 `try_acquire`
//!   读取磁盘快照。抢不到锁说明本进程或别的实例正在写，跳过本轮即可，
//!   绝不能把锁竞争变成请求失败（Issue #257）。
//!
//! 多实例语义：各实例的内存快照最迟在一个同步周期后收敛到同一份磁盘事实。
//! 轮换先发布公钥再激活；落盘截止包含 `KEY_ACTIVATION_DELAY_SECONDS` 与配置的
//! 时钟偏差围栏，因此同步间隔必须短于基础激活等待，也必须远小于
//! `key_rotation_grace_seconds`（旧公钥保留窗口）。吊销同理：非本实例执行的
//! 吊销，最长在一个同步周期后才在本实例生效。

use std::time::Duration;

use tokio::time::sleep;

use crate::clock::{Clock, SystemClock};
use crate::key_storage::{KeyStorageLock, ensure_secure_directory};
use crate::workers::WorkerContext;

use super::{KeyManager, KeyManagerError, activation, build_key_state, persistence};

/// 后台同步周期。
///
/// 取值同时受两个方向约束：太长会让别的实例刚轮换出的 `kid` 长时间验不过、
/// 让吊销迟迟不生效；太短则把密钥目录的读放大成持续 IO。5 秒远小于默认 7 天的
/// 旧公钥保留窗口，也远小于任何合理的轮换间隔。
pub const DEFAULT_KEY_SYNC_INTERVAL: Duration = Duration::from_secs(5);

/// 两次磁盘同步之间的最小间隔。
///
/// 热路径的未知 `kid` 提示来自不可信输入：任何人都能拿伪造 `kid` 的令牌打过来。
/// 这个下限保证提示最多把同步频率抬到 1/500ms，而不是跟着请求量线性放大磁盘 IO。
pub const MINIMUM_KEY_SYNC_INTERVAL: Duration = Duration::from_millis(500);

/// 一次磁盘同步的结果。调用方据此决定是否记日志，而不是把跳过当成错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySyncOutcome {
    /// 磁盘快照与内存不同，已替换内存快照。
    Updated,
    /// 磁盘快照与内存一致，未做任何改动。
    Unchanged,
    /// 目录锁被占用（本进程正在轮换，或别的实例正在写），本轮跳过。
    Contended,
    /// 纯内存模式，没有共享目录可同步。
    NotPersisted,
}

impl KeyManager {
    /// 异步同步一次磁盘快照，磁盘 IO 隔离在阻塞线程池里执行。
    pub async fn sync_from_disk(&self) -> Result<KeySyncOutcome, KeyManagerError> {
        let manager = self.clone();
        tokio::task::spawn_blocking(move || manager.sync_from_disk_blocking())
            .await
            .map_err(|_| KeyManagerError::KeyWorker)?
    }

    /// 同步一次磁盘快照，只允许在阻塞线程里调用。
    ///
    /// 目录锁必须持有到内存写入完成：轮换在同一把锁内先写文件再写内存，
    /// 提前释放会让本函数用锁外读到的旧快照覆盖掉刚完成的轮换结果。
    pub fn sync_from_disk_blocking(&self) -> Result<KeySyncOutcome, KeyManagerError> {
        let (directory, retention, skew_allowance, activation_delay) = {
            let state = self.read_state();
            (
                state.directory.clone(),
                state.retention,
                state.skew_allowance,
                state.activation_delay,
            )
        };
        let Some(directory) = directory else {
            return Ok(KeySyncOutcome::NotPersisted);
        };
        ensure_secure_directory(&directory)?;
        let _storage_lock = match KeyStorageLock::try_acquire(&directory) {
            Ok(lock) => lock,
            Err(error) if is_lock_contention(&error) => return Ok(KeySyncOutcome::Contended),
            Err(error) => return Err(KeyManagerError::Io(error)),
        };
        let now = SystemClock.now();
        let (active_key_id, key_files) =
            persistence::load_materials(&directory, retention, skew_allowance, now, false)?;
        let generation = super::journal::revocation_generation(&directory)?;
        let pending = activation::read(&directory)?;
        // 读锁绑定成独立语句后立即释放：下面的 `write_state` 是同一线程再取写锁，
        // 读锁若还活着就是自死锁。
        let unchanged = self.read_state().matches_disk_snapshot(
            &active_key_id,
            &key_files,
            pending.as_ref().map(|pending| pending.key_id.as_str()),
        );
        if self.read_state().has_replaced_materials(&key_files) {
            return Err(KeyManagerError::MaterialReplaced);
        }
        if unchanged {
            self.observe_revocation_generation(generation);
            return Ok(KeySyncOutcome::Unchanged);
        }
        let next_state = build_key_state(
            Some(directory),
            retention,
            skew_allowance,
            activation_delay,
            active_key_id,
            key_files,
            pending,
        )?;
        *self.write_state() = next_state;
        self.observe_revocation_generation(generation);
        Ok(KeySyncOutcome::Updated)
    }

    /// 后台同步任务：周期性对齐磁盘，热路径提示可提前触发下一轮。
    ///
    /// 纯内存模式不执行磁盘 IO，但仍保留一个可监督的空闲 worker；否则合法配置
    /// 会表现成关键任务意外退出。关停信号会打断定时等待，当前同步轮次则有界完成。
    pub async fn run_disk_sync_worker(self, interval: Duration, mut worker: WorkerContext) {
        let persisted = self.read_state().directory.is_some();
        let interval = interval.max(MINIMUM_KEY_SYNC_INTERVAL);
        if !persisted {
            loop {
                worker.reporter().success();
                if worker.sleep_or_shutdown(interval).await {
                    return;
                }
            }
        }
        let hint = self.resync_hint.clone();
        loop {
            worker.reporter().heartbeat();
            match self.sync_from_disk().await {
                Ok(KeySyncOutcome::Updated) => {
                    self.mark_sync_healthy(true);
                    // `kid` 是公开标识，可以入日志；私钥材料绝不出现在这里。
                    let active_key_id = self.key_id();
                    let published_key_count = self.jwks().keys.len();
                    tracing::info!(
                        active_key_id = %active_key_id,
                        published_key_count,
                        "signing key snapshot synchronized from shared storage"
                    );
                    worker.reporter().success();
                }
                Ok(KeySyncOutcome::Unchanged) | Ok(KeySyncOutcome::NotPersisted) => {
                    self.mark_sync_healthy(true);
                    worker.reporter().success();
                }
                // Contention may be a remote revocation holding the shared lock. Fail closed until
                // a complete snapshot and its generation are observed.
                Ok(KeySyncOutcome::Contended) => {
                    self.mark_sync_healthy(false);
                    worker.reporter().heartbeat();
                }
                Err(error) => {
                    self.mark_sync_healthy(false);
                    tracing::warn!(
                        error = %error,
                        "failed to synchronize signing keys from shared storage"
                    );
                    worker.reporter().retryable_failure();
                }
            }
            let hinted = tokio::select! {
                _ = worker.wait_for_shutdown() => break,
                _ = sleep(interval) => false,
                // `Notified` 在 select 中被丢弃时会把许可交还，提示不会因为
                // 定时器先到而丢失。
                _ = hint.notified() => true,
            };
            if hinted
                // 提示来自不可信输入，先压到最小间隔再同步。
                && worker
                    .sleep_or_shutdown(MINIMUM_KEY_SYNC_INTERVAL)
                    .await
            {
                break;
            }
        }
    }
}

/// 锁被占用不是故障：Unix 的 `flock` 与 Windows 的独占文件句柄都映射为
/// `WouldBlock`。`AlreadyExists` 只保留为旧实现/平台兼容边界。
fn is_lock_contention(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::AlreadyExists
    )
}
