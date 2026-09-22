//! 撤销 outbox：本地 tombstone 已提交后，异步向提供方收敛。

use std::time::Duration;

use crate::resource_services::request::RevokeLinkSessionRequest;
use crate::resource_services::store::Store;
use crate::workers::{WorkerContext, WorkerReporter};

use super::ResourceServiceService;

/// 一轮 drain 的结果。`More` / `Empty` 都不是基础设施错误。
#[derive(Clone, Copy)]
enum RevocationDrain {
    More,
    Empty,
    Failed,
}

impl ResourceServiceService {
    pub async fn run_revocation_worker(self, mut worker: WorkerContext) {
        loop {
            if worker.shutdown_requested() {
                return;
            }
            let outcome = match self.drain_revocation_outbox().await {
                Ok(true) => RevocationDrain::More,
                Ok(false) => RevocationDrain::Empty,
                Err(error) => {
                    tracing::error!(error = %error, "account portal revocation worker failed");
                    RevocationDrain::Failed
                }
            };
            // 队列还有活就立刻再来一轮。单次 drain 只处理一条，提供方超时 5 秒，
            // 小于心跳租约，不需要在 drain 里另起 heartbeat。
            if revocation_round_should_idle(worker.reporter(), outcome)
                && worker.sleep_or_shutdown(Duration::from_secs(5)).await
            {
                return;
            }
        }
    }

    async fn drain_revocation_outbox(&self) -> Result<bool, crate::sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = Store::claim_revocation_outbox(&mut tx).await? else {
            tx.commit().await?;
            return Ok(false);
        };
        tx.commit().await?;
        let Some(provider) = self.store.get_provider(row.provider_id).await? else {
            let mut tx = self.pool.begin().await?;
            Store::mark_outbox_processed(&mut tx, row.id).await?;
            tx.commit().await?;
            return Ok(true);
        };
        let client = match self.provider_client(&provider) {
            Ok(client) => client,
            Err(error) => {
                let mut tx = self.pool.begin().await?;
                Store::record_outbox_error(&mut tx, row.id, &error.to_string()).await?;
                tx.commit().await?;
                return Ok(true);
            }
        };
        let request = RevokeLinkSessionRequest::new(row.binding_id);
        let mut tx = self.pool.begin().await?;
        match client.revoke_link_session(None, &request).await {
            Ok(()) => {
                Store::mark_outbox_processed(&mut tx, row.id).await?;
            }
            Err(_) => {
                Store::record_outbox_error(&mut tx, row.id, "provider_revoke_failed").await?;
            }
        }
        tx.commit().await?;
        Ok(true)
    }
}

/// 健康的一轮（队列空或仍有条目）都记 success，并返回本轮之后是否该休眠。
///
/// 就绪探针看的是 `last_success`，不是 heartbeat。队列一直非空时只 heartbeat
/// 会让 `/health/ready` 停在 503。基础设施错误不能记成 success。
fn revocation_round_should_idle(reporter: &WorkerReporter, outcome: RevocationDrain) -> bool {
    match outcome {
        RevocationDrain::More => {
            reporter.success();
            false
        }
        RevocationDrain::Empty => {
            reporter.success();
            true
        }
        RevocationDrain::Failed => {
            reporter.retryable_failure();
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RevocationDrain, revocation_round_should_idle};
    use crate::workers::{WorkerHealth, WorkerName};

    fn success_age_is_some(health: &WorkerHealth) -> bool {
        health
            .status(WorkerName::ResourceServiceRevoke)
            .last_success_age
            .is_some()
    }

    #[test]
    fn nonempty_healthy_round_records_success_and_does_not_idle() {
        let health = WorkerHealth::new();
        let reporter = health.reporter(WorkerName::ResourceServiceRevoke);

        let should_idle = revocation_round_should_idle(&reporter, RevocationDrain::More);

        assert!(!should_idle);
        assert!(success_age_is_some(&health));
        assert_eq!(
            health
                .status(WorkerName::ResourceServiceRevoke)
                .consecutive_failures,
            0
        );
    }

    #[test]
    fn empty_healthy_round_records_success_and_idles() {
        let health = WorkerHealth::new();
        let reporter = health.reporter(WorkerName::ResourceServiceRevoke);

        let should_idle = revocation_round_should_idle(&reporter, RevocationDrain::Empty);

        assert!(should_idle);
        assert!(success_age_is_some(&health));
    }

    #[test]
    fn infrastructure_error_is_not_recorded_as_success() {
        let health = WorkerHealth::new();
        let reporter = health.reporter(WorkerName::ResourceServiceRevoke);

        let should_idle = revocation_round_should_idle(&reporter, RevocationDrain::Failed);

        assert!(should_idle);
        assert!(!success_age_is_some(&health));
        assert_eq!(
            health
                .status(WorkerName::ResourceServiceRevoke)
                .consecutive_failures,
            1
        );
    }
}
