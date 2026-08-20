//! 授权码「过期未兑换」的配额归还台账（Issue #341 / #657）。
//!
//! 配额在授权码**签发**时消耗、兑换成功时保留。若授权码过期且从未被兑换，
//! 这次消耗必须退还给 day/month 计数器，否则行为异常的 Client（或攻击者
//! 控制的回调 URL）可以反复发起授权请求、永不兑换，烧光套餐配额后触发
//! `QuotaExceeded` 拒绝真实用户。
//!
//! # 数据结构
//!
//! - ZSET `chenxing:oauth:quota:refund-pending`：member 是 reservation id，
//!   score 是授权码过期时刻的 Unix **毫秒**（Issue #522）。只有 score 已到期
//!   的成员会被 worker 处理。升级前写入的秒级 score（约 1.7e9）按
//!   「整秒过完才到期」解释，禁止在精确 `expires_at` 之前退款。
//! - 记录键 `chenxing:oauth:quota:reservation:{id}`：reservation 的 JSON
//!   序列化（含周期键），EXPIREAT 到与月度计数器相同的月边界。
//! - 周期 hash 里的 reservation id：这次 INCR 仍可退款的一次性 claim。
//! - 授权码 payload 里的 `quota_reservation_id` 把码与台账条目关联起来。
//!
//! # 兑换与退款互斥
//!
//! 周期 hash 上的 HDEL 是唯一的 claim。兑换 CAS 在删除授权码的同一 Lua
//! 事务里 HDEL 且不 DECR；退款脚本只有 HDEL 返回 1 才 DECR。worker 先
//! 快照到期 member 再退款也不再能把已兑换的配额退掉：CAS 已经把 hash
//! 拿走，随后的退款是空操作。签发失败补偿走同样的 `refund()`：授权码
//! 从未写入时 hash 还在，退款成立；已被成功兑换时 hash 已没了，空操作。

use std::time::Duration;

use redis::{AsyncCommands, Script};

use super::super::quota_scripts::{
    REFUND_SCRIPT, RESCHEDULE_REFUND_SCRIPT, SCHEDULE_REFUND_SCRIPT,
};
use super::quota_keys::{PENDING_REFUNDS_ZSET, fair_merge_due, reservation_record_key};
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

/// Scores below this are pre-#522 unix-second ZSET entries.
/// ~1973 in milliseconds; current unix seconds sit near 1.7e9.
const LEGACY_UNIX_SECOND_SCORE_LIMIT: i64 = 100_000_000_000;

/// Unix milliseconds at which an unused authorization code may be refunded.
///
/// Never earlier than `expires_at`. Leftover nanoseconds round up so the
/// worker cannot observe the member while the code is still redeemable
/// (`now >= expires_at` is the token-endpoint rule).
pub fn refund_due_unix_millis(expires_at: time::OffsetDateTime) -> i64 {
    let nanos = expires_at.unix_timestamp_nanos();
    let millis = nanos.div_euclid(1_000_000);
    let due = if nanos.rem_euclid(1_000_000) == 0 {
        millis
    } else {
        millis + 1
    };
    i64::try_from(due).unwrap_or(i64::MAX)
}

fn refund_query_unix_millis(now: time::OffsetDateTime) -> i64 {
    i64::try_from(now.unix_timestamp_nanos().div_euclid(1_000_000)).unwrap_or(i64::MAX)
}

/// 兑换授权码时原子占用配额 reservation 的参数，与授权码 CAS 在同一个 Lua 脚本里执行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaRefundCancel {
    pub(crate) zset_key: String,
    pub(crate) member: String,
    pub(crate) record_key: String,
}

impl QuotaRefundCancel {
    pub fn for_reservation(id: &str) -> Self {
        Self::for_reservation_with_keyspace(id, &RedisKeyspace::default())
    }

    pub fn for_reservation_with_keyspace(id: &str, keyspace: &RedisKeyspace) -> Self {
        Self {
            zset_key: keyspace.key(PENDING_REFUNDS_ZSET),
            member: id.to_owned(),
            record_key: reservation_record_key(keyspace, id),
        }
    }
}

impl OAuthQuotaStore {
    /// 登记一次待退条目：授权码过期仍未兑换时，worker 会退还这次配额。
    ///
    /// `expires_at` 必须是授权码的精确过期时刻。ZSET score 使用 Unix 毫秒，
    /// 且永不早于该时刻，避免秒级截断在码仍可兑换时提前退款（Issue #522）。
    pub async fn schedule_refund(
        &self,
        reservation: &QuotaReservation,
        expires_at: time::OffsetDateTime,
    ) -> Result<(), OAuthQuotaError> {
        let payload = serde_json::to_string(reservation)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: i64 = Script::new(SCHEDULE_REFUND_SCRIPT)
            .key(self.pending_refunds_key())
            .key(reservation_record_key(&self.keyspace, &reservation.id))
            .arg(refund_due_unix_millis(expires_at))
            .arg(reservation.id.as_str())
            .arg(payload.as_str())
            .arg(reservation.month_expires_at)
            .invoke_async(&mut connection)
            .await?;
        Ok(())
    }

    /// 授权码兑换失败被补偿恢复后，重新登记待退条目。
    ///
    /// CAS 已经 ZREM 掉待退成员并 HDEL 了周期 hash。记录键还在，这里把成员
    /// 加回来，同时把 hash claim 写回，否则 worker 稍后 HDEL 只能空操作，
    /// 过期未兑换的配额就退不回去。
    pub async fn reschedule_refund(
        &self,
        reservation_id: &str,
        expires_at: time::OffsetDateTime,
    ) -> Result<(), OAuthQuotaError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: i64 = Script::new(RESCHEDULE_REFUND_SCRIPT)
            .key(self.pending_refunds_key())
            .key(reservation_record_key(&self.keyspace, reservation_id))
            .arg(refund_due_unix_millis(expires_at) as f64)
            .arg(reservation_id)
            .invoke_async(&mut connection)
            .await?;
        Ok(())
    }

    /// Worker 退款：先 ZREM 待退成员，成功才 HDEL+DECR。
    ///
    /// 返回 `true` 表示这次确实减了计数。成员已被兑换 CAS 拿走时返回
    /// `false`，记录键留下给可能的补偿恢复使用。
    async fn refund_if_still_pending(
        &self,
        reservation: &QuotaReservation,
    ) -> Result<bool, OAuthQuotaError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let refunded: i64 = Script::new(REFUND_SCRIPT)
            .key(reservation.day_key.as_str())
            .key(reservation.month_key.as_str())
            .key(reservation.day_reservations_key.as_str())
            .key(reservation.month_reservations_key.as_str())
            .key(self.pending_refunds_key())
            .arg(reservation.id.as_str())
            .invoke_async(&mut connection)
            .await?;
        Ok(refunded == 1)
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
        // Millisecond scores are due when `score <= floor(now_millis)`, which
        // is exactly `now >= expires_at` for values produced by
        // `refund_due_unix_millis`. Legacy second scores are queried separately
        // with an exclusive next-second bound so mixed-version entries cannot
        // refund while the code is still redeemable.
        let now_millis = refund_query_unix_millis(now);
        let modern: Vec<String> = connection
            .zrangebyscore_limit(
                &pending_refunds_key,
                LEGACY_UNIX_SECOND_SCORE_LIMIT,
                now_millis,
                0,
                REFUND_BATCH_SIZE,
            )
            .await?;
        let legacy_max = now.unix_timestamp().saturating_sub(1);
        let legacy: Vec<String> = if legacy_max >= 0 {
            connection
                .zrangebyscore_limit(&pending_refunds_key, 0, legacy_max, 0, REFUND_BATCH_SIZE)
                .await?
        } else {
            Vec::new()
        };
        let due = fair_merge_due(modern, legacy, REFUND_BATCH_SIZE as usize);
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
            match self.refund_if_still_pending(&reservation).await {
                Ok(true) => {
                    let _: () = connection
                        .del(reservation_record_key(&self.keyspace, &reservation_id))
                        .await?;
                    refunded += 1;
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "failed to refund expired OAuth authorization quota; will retry next pass"
                    );
                }
            }
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
