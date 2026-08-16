//! 授权码「过期未兑换」的配额归还台账（Issue #341）。
//!
//! 配额在授权码**签发**时消耗、兑换成功时保留。若授权码过期且从未被兑换，
//! 这次消耗必须退还给 day/month 计数器，否则行为异常的 Client（或攻击者
//! 控制的回调 URL）可以反复发起授权请求、永不兑换，烧光套餐配额后触发
//! `QuotaExceeded` 拒绝真实用户。
//!
//! # 数据结构
//!
//! - ZSET `chenxing:oauth:quota:refund-pending`：member 是 reservation id，
//!   score 是授权码的过期时刻。只有 score 已过期的成员会被 worker 处理。
//! - 记录键 `chenxing:oauth:quota:reservation:{id}`：reservation 的 JSON
//!   序列化（含周期键），EXPIREAT 到与月度计数器相同的月边界，保证 worker
//!   在计数器存活期间总能找到退款所需的数据；周期结束后记录随计数器一起
//!   过期，退款自动退化为空操作。
//! - 授权码 payload 里的 `quota_reservation_id` 把码与台账条目关联起来。
//!
//! # 为什么兑换路径必须原子取消台账条目
//!
//! 兑换成功时配额应当保留（计数保留是正确行为）。`take_if_matches` 的 CAS
//! 脚本在删除授权码的同一个 Lua 事务里 ZREM 掉台账成员：如果分成两步，后台
//! worker 可能在两步之间看到条目，把「已兑换」的配额退掉。
//!
//! # 为什么 worker 不需要检查授权码是否还存在
//!
//! worker 只处理 score <= now 的成员，而 score（授权码过期时刻）与兑换路径
//! 的过期校验共用 `AppState` 的共享时钟：score 已过期的授权码在兑换时会被
//! `validate_code_binding` 拒绝（`now >= expires_at`），因此 worker 处理到的
//! 条目必然「过期且未兑换」，直接退款是安全的。兑换发生在过期之前的情形，
//! 其台账条目已经在 CAS 里被原子取消，worker 永远不会看到。
//!
//! 多个实例同时跑 worker 也安全：`REFUND_SCRIPT` 用 HDEL 的返回值判定谁真正
//! DECR，重复退款是幂等的空操作；ZREM 同样幂等。

use std::time::Duration;

use redis::{AsyncCommands, Script};

use super::super::quota_scripts::SCHEDULE_REFUND_SCRIPT;
use super::{OAuthQuotaError, OAuthQuotaStore, QuotaReservation};
use crate::clock::SharedClock;
use crate::redis_keyspace::RedisKeyspace;
use crate::workers::WorkerContext;

/// 后台退款任务的扫描周期。
///
/// 授权码默认 TTL 是 5 分钟，60 秒的周期意味着过期码的配额最迟在过期后约
/// 1 分钟内归还，远小于任何套餐计费窗口。
pub const QUOTA_REFUND_WORKER_INTERVAL: Duration = Duration::from_secs(60);

/// 两次扫描之间的最小间隔，防止误配把 Redis 读放大成持续扫描。
const MINIMUM_QUOTA_REFUND_INTERVAL: Duration = Duration::from_secs(1);

/// 每轮最多处理的过期条目数：一轮处理不完留到下一轮，不长时间占住连接。
const REFUND_BATCH_SIZE: isize = 100;

/// 待退台账 ZSET：member = reservation id，score = 授权码过期时刻。
pub(crate) const PENDING_REFUNDS_ZSET: &str = "chenxing:oauth:quota:refund-pending";

fn reservation_record_key(keyspace: &RedisKeyspace, reservation_id: &str) -> String {
    keyspace.key(&format!(
        "chenxing:oauth:quota:reservation:{reservation_id}"
    ))
}

/// 兑换授权码时原子取消待退条目的参数，与授权码 CAS 在同一个 Lua 脚本里执行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaRefundCancel {
    pub(crate) zset_key: String,
    pub(crate) member: String,
}

impl QuotaRefundCancel {
    pub fn for_reservation(id: &str) -> Self {
        Self::for_reservation_with_keyspace(id, &RedisKeyspace::default())
    }

    pub fn for_reservation_with_keyspace(id: &str, keyspace: &RedisKeyspace) -> Self {
        Self {
            zset_key: keyspace.key(PENDING_REFUNDS_ZSET),
            member: id.to_owned(),
        }
    }
}

impl OAuthQuotaStore {
    /// 登记一次待退条目：授权码过期仍未兑换时，worker 会退还这次配额。
    pub async fn schedule_refund(
        &self,
        reservation: &QuotaReservation,
        refund_at_unix: i64,
    ) -> Result<(), OAuthQuotaError> {
        let payload = serde_json::to_string(reservation)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: i64 = Script::new(SCHEDULE_REFUND_SCRIPT)
            .key(self.pending_refunds_key())
            .key(reservation_record_key(&self.keyspace, &reservation.id))
            .arg(refund_at_unix)
            .arg(reservation.id.as_str())
            .arg(payload.as_str())
            .arg(reservation.month_expires_at)
            .invoke_async(&mut connection)
            .await?;
        Ok(())
    }

    /// 授权码兑换失败被补偿恢复后，重新登记待退条目。
    ///
    /// CAS 脚本在原子消费时已经 ZREM 掉原成员；记录键没有被删除，因此这里
    /// 只需要把成员加回来。恢复的授权码仍可能在新的过期时刻之前被兑换
    /// （CAS 再次原子取消），也可能再次过期未兑换（worker 凭记录退款）。
    pub async fn reschedule_refund(
        &self,
        reservation_id: &str,
        refund_at_unix: i64,
    ) -> Result<(), OAuthQuotaError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: () = connection
            .zadd(
                self.pending_refunds_key(),
                reservation_id,
                refund_at_unix as f64,
            )
            .await?;
        Ok(())
    }

    /// 处理一批已过期的待退条目：先退还配额，再清掉台账数据。
    ///
    /// 返回本轮处理的条目数。退款失败（Redis 不可用等）时保留条目，下一轮
    /// 重试；退款脚本幂等，worker 崩溃后重启重复处理也只是空操作。
    pub async fn run_refund_worker_pass(
        &self,
        now: time::OffsetDateTime,
    ) -> Result<usize, OAuthQuotaError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let pending_refunds_key = self.pending_refunds_key();
        let due: Vec<String> = connection
            .zrangebyscore_limit(
                &pending_refunds_key,
                0,
                now.unix_timestamp(),
                0,
                REFUND_BATCH_SIZE,
            )
            .await?;
        let mut refunded = 0usize;
        for reservation_id in due {
            let record: Option<String> = connection
                .get(reservation_record_key(&self.keyspace, &reservation_id))
                .await?;
            let Some(payload) = record else {
                // 记录键缺失：只有月边界过期或从未成功登记两种可能，此时周期
                // 计数器同样已过期，退款是空操作，直接清理成员即可。
                let _: () = connection
                    .zrem(&pending_refunds_key, &reservation_id)
                    .await?;
                continue;
            };
            let reservation: QuotaReservation = match serde_json::from_str(&payload) {
                Ok(reservation) => reservation,
                Err(error) => {
                    tracing::warn!(error = %error, "dropping malformed OAuth quota refund record");
                    let _: () = connection
                        .zrem(&pending_refunds_key, &reservation_id)
                        .await?;
                    let _: () = connection
                        .del(reservation_record_key(&self.keyspace, &reservation_id))
                        .await?;
                    continue;
                }
            };
            if let Err(error) = self.refund(&reservation).await {
                tracing::warn!(
                    error = %error,
                    "failed to refund expired OAuth authorization quota; will retry next pass"
                );
                continue;
            }
            let _: () = connection
                .zrem(&pending_refunds_key, &reservation_id)
                .await?;
            let _: () = connection
                .del(reservation_record_key(&self.keyspace, &reservation_id))
                .await?;
            refunded += 1;
        }
        Ok(refunded)
    }

    pub fn refund_cancel(&self, reservation_id: &str) -> QuotaRefundCancel {
        QuotaRefundCancel::for_reservation_with_keyspace(reservation_id, &self.keyspace)
    }

    fn pending_refunds_key(&self) -> String {
        self.keyspace.key(PENDING_REFUNDS_ZSET)
    }

    /// 后台退款任务：周期性扫描到期条目并退还配额。
    ///
    /// 多实例部署下每个实例都会跑这个 worker，退款与清理都幂等，重复处理无害。
    /// 启动后立即先跑一轮，把停机期间积压的到期条目清掉；关停会完成当前批次，
    /// 然后在下一次等待点退出。
    pub async fn run_refund_worker(
        self,
        clock: SharedClock,
        interval: Duration,
        mut worker: WorkerContext,
    ) {
        let interval = interval.max(MINIMUM_QUOTA_REFUND_INTERVAL);
        loop {
            worker.reporter().heartbeat();
            match self.run_refund_worker_pass(clock.now()).await {
                Ok(0) => worker.reporter().success(),
                Ok(processed) => {
                    tracing::info!(
                        processed,
                        "refunded expired OAuth authorization quota reservations"
                    );
                    worker.reporter().success();
                }
                Err(error) => {
                    tracing::warn!(error = %error, "OAuth quota refund worker pass failed");
                    worker.reporter().retryable_failure();
                }
            }
            if worker.sleep_or_shutdown(interval).await {
                break;
            }
        }
    }
}
