//! 撤销 outbox：本地 tombstone 已提交后，异步向提供方收敛。

use std::time::Duration;

use crate::resource_services::request::RevokeLinkSessionRequest;
use crate::resource_services::store::Store;
use crate::workers::WorkerContext;

use super::ResourceServiceService;

impl ResourceServiceService {
    pub async fn run_revocation_worker(self, mut worker: WorkerContext) {
        loop {
            if worker.shutdown_requested() {
                return;
            }
            match self.drain_revocation_outbox().await {
                Ok(true) => worker.reporter().heartbeat(),
                Ok(false) => {
                    worker.reporter().success();
                    if worker.sleep_or_shutdown(Duration::from_secs(5)).await {
                        return;
                    }
                }
                Err(error) => {
                    tracing::error!(error = %error, "account portal revocation worker failed");
                    worker.reporter().retryable_failure();
                    if worker.sleep_or_shutdown(Duration::from_secs(5)).await {
                        return;
                    }
                }
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
        let revoked = client.revoke_link_session(None, &request).await;
        let mut tx = self.pool.begin().await?;
        match revoked {
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
