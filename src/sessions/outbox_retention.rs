//! Session outbox 的终态治理：保留窗口、有界清理和 dead-letter。
//!
//! Issue #275。投递逻辑（领取、应用到 Redis）在父模块，本模块只回答三个问题：
//!
//! 1. 一个事件什么时候不再重试？—— [`SessionOutboxPolicy::max_attempts`]
//! 2. 终态事件什么时候可以删？—— 两个保留窗口，按终态类别分开
//! 3. 一次删多少？—— [`SessionOutboxPolicy::cleanup_batch`]，有界批量
//!
//! 把这些放在一起是因为它们是同一个决策的三面：outbox 表必须有界。缺任何一面
//! 都会退回 Issue #275 的状态——已处理行永久堆积，或者永久失败的行每 5 分钟被
//! 重新领取一次直到部署寿命结束。

use std::time::Duration;

use crate::{
    sessions::store::{SessionStore, SessionStoreError},
    workers::WorkerContext,
};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// 保留窗口的上限，与 `AUDIT_RETENTION_DAYS` 的上限一致（100 年）。
///
/// 存在的意义是保证换算成 SQL `INTERVAL` 时不会溢出：`Duration` 能表示的秒数
/// 远超 PostgreSQL interval 的范围。
const MAX_RETENTION: Duration = Duration::from_secs(36_500 * 24 * 60 * 60);

/// 单批清理的行数上限，与审计归档的批量上限一致。
const MAX_CLEANUP_BATCH: u32 = 10_000;

/// Session outbox 的终态策略。
///
/// 所有字段都经过 [`Self::sanitized`] 收敛到可用区间：零批量会让清理循环空转，
/// 零尝试次数会让每个事件在第一次投递前就被判死，两者都是配置事故而不是策略。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionOutboxPolicy {
    pub processed_retention: Duration,
    pub dead_letter_retention: Duration,
    pub cleanup_batch: u32,
    pub cleanup_interval: Duration,
    pub max_attempts: i32,
}

impl Default for SessionOutboxPolicy {
    fn default() -> Self {
        Self {
            // 成功行只有取证价值：确认某次登录或撤销确实投递到了 Redis。一天
            // 足够覆盖"昨天有人报告会话异常"这类排查，再长就只是账单。
            processed_retention: DAY,
            // dead-letter 行是"Redis 投影确定丢失"的审计记录，比成功行重要得多：
            // 一条撤销事件进入 dead-letter 意味着某个会话的投影可能仍然存在。
            // 30 天给运维现实的发现和处置窗口。
            dead_letter_retention: 30 * DAY,
            cleanup_batch: 500,
            cleanup_interval: Duration::from_secs(300),
            // 退避上限 5 分钟，10 次尝试覆盖约 20 分钟的真实故障窗口——足够撑过
            // Redis 重启、主从切换和网络分区。撑不过去的是配置错误或数据损坏，
            // 重试一万次也不会变好，只会把坏行永久留在待处理索引的头部。
            max_attempts: 10,
        }
    }
}

impl SessionOutboxPolicy {
    /// 把取值收敛到可用区间。构造器在应用策略前调用，调用方无需自己校验。
    pub fn sanitized(self) -> Self {
        Self {
            processed_retention: self
                .processed_retention
                .clamp(Duration::from_secs(1), MAX_RETENTION),
            dead_letter_retention: self
                .dead_letter_retention
                .clamp(Duration::from_secs(1), MAX_RETENTION),
            cleanup_batch: self.cleanup_batch.clamp(1, MAX_CLEANUP_BATCH),
            cleanup_interval: self.cleanup_interval.max(Duration::from_secs(1)),
            max_attempts: self.max_attempts.max(1),
        }
    }

    fn processed_retention_interval(&self) -> time::Duration {
        retention_interval(self.processed_retention)
    }

    fn dead_letter_retention_interval(&self) -> time::Duration {
        retention_interval(self.dead_letter_retention)
    }

    fn cleanup_limit(&self) -> i64 {
        i64::from(self.cleanup_batch)
    }
}

/// 保留窗口换算成 SQL `INTERVAL`。
///
/// 输入已被 [`SessionOutboxPolicy::sanitized`] 限制在 `MAX_RETENTION` 以内，
/// 这里的下限和 `try_from` 兜底只是防御性的：秒数在 i64 范围内是无条件成立的。
fn retention_interval(retention: Duration) -> time::Duration {
    time::Duration::seconds(
        i64::try_from(retention.min(MAX_RETENTION).as_secs())
            .unwrap_or(i64::MAX)
            .max(1),
    )
}

/// 一次清理的结果，按终态类别分开计数。
///
/// 分开计数不是为了好看：调度需要知道"哪一类跑满了批量"才能判断还有没有积压。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutboxCleanup {
    pub processed: u64,
    pub dead_lettered: u64,
}

impl OutboxCleanup {
    pub fn total(&self) -> u64 {
        self.processed.saturating_add(self.dead_lettered)
    }

    /// 是否有任一类别跑满批量。跑满意味着还有更多可删的行在等着。
    pub fn is_saturated(&self, batch: u32) -> bool {
        let batch = u64::from(batch);
        self.processed >= batch || self.dead_lettered >= batch
    }
}

impl SessionStore {
    /// 删除超出保留窗口的终态事件，每个类别最多一批。
    ///
    /// 两条 DELETE 而不是一条 UNION：每个类别有自己的保留窗口和自己的部分索引，
    /// 合并后 planner 只能扫一个更宽的集合再过滤，而且拿不到分类别的计数。
    ///
    /// `FOR UPDATE SKIP LOCKED` 让多实例的清理互相让路而不是排队等锁。删除本身
    /// 是幂等的，两个实例删到同一批也只是其中一个少删几行。
    ///
    /// 待处理和 dead-letter 之外的行不受影响：`WHERE` 条件要求终态时间戳非空，
    /// 因此正在重试的事件不可能被清理掉。
    pub async fn prune_settled_outbox(&self) -> Result<OutboxCleanup, SessionStoreError> {
        let Some(pool) = &self.metadata else {
            return Ok(OutboxCleanup::default());
        };
        let policy = self.outbox_policy;

        let processed = crate::sqlx::query(
            "WITH expired AS (
                 SELECT id
                 FROM session_outbox
                 WHERE processed_at IS NOT NULL
                   AND processed_at < NOW() - $1
                 ORDER BY processed_at, id
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
             )
             DELETE FROM session_outbox AS outbox
             USING expired
             WHERE outbox.id = expired.id",
        )
        .bind(policy.processed_retention_interval())
        .bind(policy.cleanup_limit())
        .execute(pool)
        .await?
        .rows_affected();

        let dead_lettered = crate::sqlx::query(
            "WITH expired AS (
                 SELECT id
                 FROM session_outbox
                 WHERE dead_lettered_at IS NOT NULL
                   AND dead_lettered_at < NOW() - $1
                 ORDER BY dead_lettered_at, id
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
             )
             DELETE FROM session_outbox AS outbox
             USING expired
             WHERE outbox.id = expired.id",
        )
        .bind(policy.dead_letter_retention_interval())
        .bind(policy.cleanup_limit())
        .execute(pool)
        .await?
        .rows_affected();

        Ok(OutboxCleanup {
            processed,
            dead_lettered,
        })
    }

    /// 记录一次投递失败：安排退避重试，或者在尝试预算耗尽时转入 dead-letter。
    ///
    /// `attempts` 是领取时自增后的值，因此 `attempts >= max_attempts` 表示这次
    /// 失败就是最后一次。dead-letter 行保留 `attempts` 和 `last_error`，是这个
    /// 事件为什么被放弃的完整审计记录；它同时退出待处理索引，不会再被领取。
    pub(super) async fn record_delivery_failure(
        &self,
        pool: &crate::sqlx::PgPool,
        entry: &super::OutboxEntry,
        error_value: &SessionStoreError,
    ) -> Result<(), SessionStoreError> {
        let outcome = if entry.attempts >= self.outbox_policy.max_attempts {
            let outcome = crate::sqlx::query(
                "UPDATE session_outbox
                 SET dead_lettered_at = NOW(), last_error = $4
                 WHERE id = $1 AND processed_at IS NULL AND claim_generation = $2 AND claim_token = $3",
            )
            .bind(entry.id)
            .bind(entry.claim_generation)
            .bind(&entry.claim_token)
            .bind(error_value.to_string())
            .execute(pool)
            .await?;
            if outcome.rows_affected() == 1 {
                tracing::error!(
                    outbox_id = entry.id,
                    operation = %entry.operation,
                    attempts = entry.attempts,
                    max_attempts = self.outbox_policy.max_attempts,
                    error = %error_value,
                    "session Redis projection dead-lettered after exhausting delivery attempts"
                );
            }
            outcome
        } else {
            let delay_seconds = 2_i64
                .saturating_pow(entry.attempts.saturating_sub(1) as u32)
                .min(300);
            let outcome = crate::sqlx::query(
                "UPDATE session_outbox
                 SET available_at = NOW() + $4, last_error = $5
                 WHERE id = $1 AND processed_at IS NULL AND claim_generation = $2 AND claim_token = $3",
            )
            .bind(entry.id)
            .bind(entry.claim_generation)
            .bind(&entry.claim_token)
            .bind(time::Duration::seconds(delay_seconds))
            .bind(error_value.to_string())
            .execute(pool)
            .await?;
            if outcome.rows_affected() == 1 {
                tracing::error!(
                    outbox_id = entry.id,
                    operation = %entry.operation,
                    attempts = entry.attempts,
                    retry_in_seconds = delay_seconds,
                    error = %error_value,
                    "session Redis projection failed; retry scheduled"
                );
            }
            outcome
        };
        if outcome.rows_affected() == 0 {
            tracing::warn!(
                outbox_id = entry.id,
                claim_generation = entry.claim_generation,
                event = "session_outbox.stale_claim",
                "stale session outbox failure ignored"
            );
        }
        Ok(())
    }

    /// 投递循环，附带按间隔触发的终态清理。
    ///
    /// 清理在启动时先跑一轮（`next_cleanup` 初值为当前时刻）：升级到本版本的部署
    /// 很可能带着历史积压，等一个完整间隔没有意义。批量跑满说明还有可删的行，
    /// 下一轮循环立刻再清一批而不是等满间隔——积压只有这样才收敛。
    ///
    /// 清理失败按正常间隔重试。它不影响投递，不值得让投递循环跟着退避。
    pub async fn run_outbox_worker(self, mut worker: WorkerContext) {
        let policy = self.outbox_policy;
        let mut next_cleanup = tokio::time::Instant::now();
        loop {
            worker.reporter().heartbeat();
            let mut pass_failed = false;
            match self.process_pending_outbox().await {
                Ok(_) => {}
                Err(error_value) => {
                    pass_failed = true;
                    tracing::error!(error = %error_value, "session outbox worker failed");
                }
            }
            if tokio::time::Instant::now() >= next_cleanup {
                // 下一次到期时间以清理"结束"时刻为基准，而不是开始时刻：清理本身
                // 可能不快，用开始时刻会让间隔被执行时间吃掉。
                next_cleanup = match self.prune_settled_outbox().await {
                    Ok(cleanup) => {
                        if cleanup.total() > 0 {
                            tracing::info!(
                                processed_removed = cleanup.processed,
                                dead_letter_removed = cleanup.dead_lettered,
                                "session outbox retention batch removed settled events"
                            );
                        }
                        if cleanup.is_saturated(policy.cleanup_batch) {
                            tokio::time::Instant::now()
                        } else {
                            tokio::time::Instant::now() + policy.cleanup_interval
                        }
                    }
                    Err(error_value) => {
                        pass_failed = true;
                        tracing::error!(error = %error_value, "session outbox retention failed");
                        tokio::time::Instant::now() + policy.cleanup_interval
                    }
                };
            }
            if pass_failed {
                worker.reporter().retryable_failure();
            } else {
                worker.reporter().success();
            }
            if worker.sleep_or_shutdown(Duration::from_secs(1)).await {
                break;
            }
        }
    }
}

#[cfg(test)]
#[path = "outbox_retention_tests.rs"]
mod tests;
