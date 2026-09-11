use crate::workers::WorkerContext;

use super::AppState;

impl AppState {
    /// 周期性回读 Issuer generation。通知只负责降低延迟，轮询才是 PgBouncer 与
    /// 断线场景下的可靠收敛上界；读取失败保留最后一个合法快照。
    pub async fn run_issuer_sync_worker(self, mut worker: WorkerContext) {
        let mut interval = tokio::time::interval(crate::settings::ISSUER_SYNC_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = worker.wait_for_shutdown() => break,
                _ = interval.tick() => {}
            }
            worker.reporter().heartbeat();
            let expected = self.issuer.state();
            match crate::settings::issuer::load_raw(&self.database).await {
                Ok(record) => match self
                    .issuer
                    .apply_raw_if_unchanged(&expected, record.as_ref())
                {
                    Ok(Some(snapshot)) => {
                        tracing::info!(
                            event = "issuer.runtime_applied",
                            generation = snapshot.generation(),
                            issuer = %snapshot.issuer(),
                            "applied persisted issuer to the running instance"
                        );
                        worker.reporter().success();
                    }
                    Ok(None) => worker.reporter().success(),
                    Err(error_value) => {
                        tracing::error!(
                            event = "issuer.runtime_invalid",
                            generation = record.as_ref().map(|record| record.generation),
                            error = %error_value,
                            "persisted issuer is invalid; protocol routes are fail-closed"
                        );
                        worker.reporter().retryable_failure();
                    }
                },
                Err(error_value) => {
                    tracing::warn!(
                        event = "issuer.runtime_reload_failed",
                        error = %error_value,
                        "failed to reload issuer; retaining the last runtime state"
                    );
                    worker.reporter().retryable_failure();
                }
            }
        }
    }
}
