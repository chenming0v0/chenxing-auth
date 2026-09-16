//! OAuth Client deletion.

use super::{ClientService, ClientServiceError};
use crate::clients::repository;
use crate::users::domain::UserId;

impl ClientService {
    pub async fn delete_with_audit(
        &self,
        client_id: &str,
        audit_event: crate::audit::AuditEvent,
    ) -> Result<bool, ClientServiceError> {
        self.delete_in_scope_with_audit(None, client_id, audit_event)
            .await
    }

    pub async fn delete_for_user_with_audit(
        &self,
        owner_user_id: UserId,
        client_id: &str,
        audit_event: crate::audit::AuditEvent,
    ) -> Result<bool, ClientServiceError> {
        self.delete_in_scope_with_audit(Some(owner_user_id), client_id, audit_event)
            .await
    }

    async fn delete_in_scope_with_audit(
        &self,
        owner_user_id: Option<UserId>,
        client_id: &str,
        audit_event: crate::audit::AuditEvent,
    ) -> Result<bool, ClientServiceError> {
        let deleted =
            repository::delete_client_with_audit(&self.pool, owner_user_id, client_id, audit_event)
                .await
                .map_err(|error| match error {
                    repository::AuditedClientMutationError::Database(error) => {
                        ClientServiceError::Database(error)
                    }
                    repository::AuditedClientMutationError::Audit(error) => {
                        tracing::error!(event = "client_delete.audit_unavailable", error = %error);
                        ClientServiceError::AuditUnavailable
                    }
                })?;
        if deleted {
            self.revoke_refresh_tokens_best_effort(
                client_id,
                super::rotation::RefreshTokenCleanupReason::ClientDeleted,
            )
            .await;
        }
        Ok(deleted)
    }
}
