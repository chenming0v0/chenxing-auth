use time::Duration;
use uuid::Uuid;

use crate::users::{
    UserSessionCredential, UserSessionValidation, validate_user_session_in_transaction,
};

use super::ResourceServiceService;
use crate::resource_services::bundle::{RefreshBinding, TokenBundle};
use crate::resource_services::fingerprint::{
    fingerprint_hmac_key, keyed_fingerprint, refresh_message,
};
use crate::resource_services::request::RefreshLinkSessionRequest;
use crate::resource_services::scalar::UtcTime;
use crate::resource_services::service_error::ServiceError;
use crate::resource_services::store::{
    ClaimedOperation, CommittedBundle, OperationLease, Store, StoreError,
};
use crate::resource_services::types::{
    ExistingOperation, OPERATION_REFRESH, classify_existing_operation,
};
use crate::resource_services::views::BindingView;

impl ResourceServiceService {
    pub async fn refresh_binding(
        &self,
        credential: UserSessionCredential,
        binding_id: Uuid,
        idempotency_key: Uuid,
    ) -> Result<BindingView, ServiceError> {
        let now = self.clock.now();
        let mut tx = self.pool.begin().await?;
        match validate_user_session_in_transaction(&mut tx, credential).await? {
            UserSessionValidation::Valid => {}
            other => return Err(ServiceError::from(other)),
        }
        let Some(binding) = Store::lock_binding(&mut tx, binding_id).await? else {
            return Err(ServiceError::BindingNotFound);
        };
        if binding.user_id != credential.user_id || !binding.is_live() {
            return Err(ServiceError::BindingTombstoned);
        }
        let Some(provider) = Store::lock_provider(&mut tx, binding.provider_id).await? else {
            return Err(ServiceError::ProviderNotFound);
        };
        if !provider.enabled {
            return Err(ServiceError::ProviderDisabled);
        }
        let ciphertext = binding
            .token_bundle_ciphertext
            .as_deref()
            .ok_or(ServiceError::ReauthorizationRequired)?;
        let plaintext = self.decrypt_bundle(provider.id, binding.id, ciphertext)?;
        let stored =
            TokenBundle::parse(plaintext.expose().as_bytes()).map_err(ServiceError::Protocol)?;
        let hmac_key =
            fingerprint_hmac_key(self.decrypt_provider_secret(&provider)?.expose().as_bytes());
        let fingerprint = keyed_fingerprint(
            &hmac_key,
            &refresh_message(
                provider.id,
                binding.id,
                credential.user_id,
                stored.refresh_token.expose().as_bytes(),
            ),
        );
        let lease = OperationLease {
            idempotency_key,
            provider_id: provider.id,
            binding_id: binding.id,
            user_id: credential.user_id,
            operation_type: OPERATION_REFRESH.to_owned(),
            request_fingerprint: fingerprint.clone(),
            provider_revision: provider.revision,
        };
        let claimed = Store::claim_operation(&mut tx, lease.clone())
            .await
            .map_err(map_store)?;
        if let ClaimedOperation::Existing(existing) = &claimed {
            match classify_existing_operation(existing, &fingerprint, now) {
                ExistingOperation::ReplayCommitted => {
                    tx.commit().await?;
                    return Ok(BindingView::from_row(&binding));
                }
                ExistingOperation::FingerprintConflict | ExistingOperation::Failed => {
                    return Err(ServiceError::Conflict);
                }
                ExistingOperation::ReplayInFlight => {}
                ExistingOperation::ReclaimExpiredLease => {
                    Store::reclaim_expired_lease(&mut tx, &lease).await?;
                }
            }
        }
        tx.commit().await?;
        let grant_id = binding
            .grant_id
            .ok_or(ServiceError::ReauthorizationRequired)?;
        let grant_expires_at = binding
            .grant_expires_at
            .ok_or(ServiceError::ReauthorizationRequired)?;
        let request = RefreshLinkSessionRequest::new(binding.id, stored.refresh_token);
        let expected = RefreshBinding {
            grant_id,
            uid: &binding.uid,
            grant_expires_at: UtcTime::from_datetime(grant_expires_at),
        };
        let client = self.provider_client(&provider)?;
        match client
            .refresh_link_session(idempotency_key, &request, &expected)
            .await
        {
            Ok(bundle) => {
                let mut tx = self.pool.begin().await?;
                match validate_user_session_in_transaction(&mut tx, credential).await? {
                    UserSessionValidation::Valid => {}
                    other => return Err(ServiceError::from(other)),
                }
                let Some(current) = Store::lock_binding(&mut tx, binding.id).await? else {
                    return Err(ServiceError::BindingNotFound);
                };
                if !current.is_live() {
                    return Err(ServiceError::BindingTombstoned);
                }
                let plaintext = bundle.to_storage_plaintext();
                let ciphertext = self.encrypt_bundle(provider.id, binding.id, &plaintext)?;
                let committed = Store::commit_refreshed_binding(
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
                    OPERATION_REFRESH,
                    idempotency_key,
                )
                .await?;
                tx.commit().await?;
                Ok(BindingView::from_row(&committed))
            }
            Err(error) => {
                self.handle_provider_error(
                    provider.id,
                    OPERATION_REFRESH,
                    idempotency_key,
                    binding.id,
                    binding.generation,
                    error,
                )
                .await
            }
        }
    }
}

fn map_store(error: StoreError) -> ServiceError {
    match error {
        StoreError::IssuerTaken
        | StoreError::SlugTaken
        | StoreError::ScopeTaken
        | StoreError::Conflict
        | StoreError::UserSlotTaken
        | StoreError::UidTaken => ServiceError::Conflict,
        StoreError::Database(error) => ServiceError::from(error),
    }
}
