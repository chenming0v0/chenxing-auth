use time::Duration;
use uuid::Uuid;

use crate::users::{
    UserSessionCredential, UserSessionValidation, validate_user_session_in_transaction,
};

use super::AccountPortalService;
use crate::account_portal::bundle::TokenBundle;
use crate::account_portal::request::CreateLinkSessionRequest;
use crate::account_portal::service_error::ServiceError;
use crate::account_portal::store::{
    ClaimedOperation, CommittedBundle, OperationLease, PendingBinding, Store, StoreError,
    operation_fingerprint,
};
use crate::account_portal::types::{
    ExistingOperation, OPERATION_CREATE, classify_existing_operation,
};
use crate::account_portal::views::BindingView;

impl AccountPortalService {
    pub async fn create_binding(
        &self,
        credential: UserSessionCredential,
        provider_id: Uuid,
        idempotency_key: Uuid,
        identifier: String,
        secret: String,
    ) -> Result<BindingView, ServiceError> {
        let now = self.clock.now();
        let mut tx = self.pool.begin().await?;
        match validate_user_session_in_transaction(&mut tx, credential).await? {
            UserSessionValidation::Valid => {}
            other => return Err(ServiceError::from(other)),
        }
        let Some(provider) = Store::lock_provider(&mut tx, provider_id).await? else {
            return Err(ServiceError::ProviderNotFound);
        };
        if !provider.enabled {
            return Err(ServiceError::ProviderDisabled);
        }
        let live =
            Store::lock_live_binding_for_user(&mut tx, provider_id, credential.user_id).await?;
        let binding_id = match live.as_ref() {
            Some(existing) if !existing.uid.is_empty() => {
                tx.commit().await?;
                return Ok(BindingView::from_row(existing));
            }
            Some(existing) => existing.id,
            None => Uuid::new_v4(),
        };
        let fingerprint = operation_fingerprint(
            OPERATION_CREATE,
            provider_id,
            Uuid::nil(),
            credential.user_id,
        );
        let lease = OperationLease {
            idempotency_key,
            provider_id,
            binding_id,
            user_id: credential.user_id,
            operation_type: OPERATION_CREATE.to_owned(),
            request_fingerprint: fingerprint.clone(),
            provider_revision: provider.revision,
        };
        let claimed = Store::claim_operation(&mut tx, lease.clone())
            .await
            .map_err(map_store)?;
        let (binding, operation, should_call) = match claimed {
            ClaimedOperation::Existing(existing) => {
                match classify_existing_operation(&existing, &fingerprint, now) {
                    ExistingOperation::ReplayCommitted => {
                        let row = self
                            .store
                            .get_binding(existing.binding_id)
                            .await?
                            .ok_or(ServiceError::BindingNotFound)?;
                        tx.commit().await?;
                        return Ok(BindingView::from_row(&row));
                    }
                    ExistingOperation::FingerprintConflict | ExistingOperation::Failed => {
                        return Err(ServiceError::Conflict);
                    }
                    ExistingOperation::ReplayInFlight => {
                        let Some(binding) =
                            Store::lock_binding(&mut tx, existing.binding_id).await?
                        else {
                            return Err(ServiceError::BindingNotFound);
                        };
                        if binding.user_id != credential.user_id {
                            return Err(ServiceError::BindingNotFound);
                        }
                        (binding, existing, true)
                    }
                    ExistingOperation::ReclaimExpiredLease => {
                        Store::reclaim_expired_lease(&mut tx, &lease).await?;
                        let Some(binding) =
                            Store::lock_binding(&mut tx, existing.binding_id).await?
                        else {
                            return Err(ServiceError::BindingNotFound);
                        };
                        if binding.user_id != credential.user_id {
                            return Err(ServiceError::BindingNotFound);
                        }
                        (binding, existing, true)
                    }
                }
            }
            ClaimedOperation::Created(operation) => {
                let binding = match live {
                    Some(existing) => existing,
                    None => Store::insert_pending_binding(
                        &mut tx,
                        PendingBinding {
                            id: binding_id,
                            provider_id,
                            user_id: credential.user_id,
                            issuer: provider.issuer.clone(),
                        },
                    )
                    .await
                    .map_err(map_store)?,
                };
                (binding, operation, true)
            }
        };
        tx.commit().await?;
        if !should_call {
            return Ok(BindingView::from_row(&binding));
        }
        let request = CreateLinkSessionRequest::new(binding.id, identifier, secret)
            .map_err(|_| ServiceError::InvalidInput("credentials"))?;
        let client = self.provider_client(&provider)?;
        match client.create_link_session(idempotency_key, &request).await {
            Ok(bundle) => {
                self.commit_created(credential, &provider, &binding, &operation, bundle)
                    .await
            }
            Err(error) => {
                self.fail_operation(provider.id, OPERATION_CREATE, idempotency_key)
                    .await?;
                Err(ServiceError::from(error))
            }
        }
    }

    async fn commit_created(
        &self,
        credential: UserSessionCredential,
        provider: &crate::account_portal::types::ProviderRow,
        binding: &crate::account_portal::types::BindingRow,
        operation: &crate::account_portal::types::OperationRow,
        bundle: TokenBundle,
    ) -> Result<BindingView, ServiceError> {
        let now = self.clock.now();
        let mut tx = self.pool.begin().await?;
        match validate_user_session_in_transaction(&mut tx, credential).await? {
            UserSessionValidation::Valid => {}
            other => return Err(ServiceError::from(other)),
        }
        let Some(provider_locked) = Store::lock_provider(&mut tx, provider.id).await? else {
            return Err(ServiceError::ProviderNotFound);
        };
        if provider_locked.revision != operation.provider_revision {
            return Err(ServiceError::Conflict);
        }
        let Some(current) = Store::lock_binding(&mut tx, binding.id).await? else {
            return Err(ServiceError::BindingNotFound);
        };
        if !current.is_live() || current.user_id != credential.user_id {
            return Err(ServiceError::BindingTombstoned);
        }
        let plaintext = bundle.to_storage_plaintext();
        let ciphertext = self.encrypt_bundle(provider.id, binding.id, &plaintext)?;
        let committed = Store::commit_created_binding(
            &mut tx,
            CommittedBundle {
                binding_id: binding.id,
                expected_generation: current.generation,
                uid: bundle.uid.clone(),
                grant_id: bundle.grant_id,
                grant_expires_at: bundle.grant_expires_at.as_datetime(),
                token_bundle_ciphertext: ciphertext,
                snapshot_json: bundle.snapshot.to_value(),
                access_expires_at: now + Duration::seconds(bundle.expires_in as i64),
                refresh_expires_at: bundle.refresh_expires_at.as_datetime(),
            },
        )
        .await
        .map_err(map_store)?;
        Store::mark_operation_committed(
            &mut tx,
            provider.id,
            OPERATION_CREATE,
            operation.idempotency_key,
        )
        .await?;
        tx.commit().await?;
        Ok(BindingView::from_row(&committed))
    }
}

fn map_store(error: StoreError) -> ServiceError {
    match error {
        StoreError::IssuerTaken
        | StoreError::Conflict
        | StoreError::UserSlotTaken
        | StoreError::UidTaken => ServiceError::Conflict,
        StoreError::Database(error) => ServiceError::from(error),
    }
}
