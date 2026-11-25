use time::Duration;
use uuid::Uuid;

use crate::users::UserSessionCredential;

use super::ResourceServiceService;
use super::access::BindingAccess;
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
        self.refresh_authorized(
            BindingAccess::Browser(credential),
            binding_id,
            idempotency_key,
        )
        .await
    }

    pub(super) async fn refresh_authorized(
        &self,
        access: BindingAccess,
        binding_id: Uuid,
        idempotency_key: Uuid,
    ) -> Result<BindingView, ServiceError> {
        let now = self.clock.now();
        let mut tx = self.pool.begin().await?;
        access.validate(&mut tx).await?;
        let Some(binding) = Store::lock_binding(&mut tx, binding_id).await? else {
            return Err(ServiceError::BindingNotFound);
        };
        if binding.user_id != access.user_id() || !binding.is_live() {
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
            &refresh_message(provider.id, binding.id, access.user_id()),
        );
        let lease = OperationLease {
            idempotency_key,
            provider_id: provider.id,
            binding_id: binding.id,
            user_id: access.user_id(),
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
                    let row = self
                        .store
                        .get_binding(existing.binding_id)
                        .await?
                        .ok_or(ServiceError::BindingNotFound)?;
                    if row.user_id != access.user_id() {
                        return Err(ServiceError::BindingNotFound);
                    }
                    tx.commit().await?;
                    return Ok(BindingView::from_row(&row));
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
        let snapshot_revision = Store::reserve_snapshot_revision(&mut tx, binding.id).await?;
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
                        snapshot_revision: Some(snapshot_revision),
                        expected_provider_revision: provider.revision,
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
                let snapshot_applied =
                    Store::observation_is_current(&mut tx, binding.id, snapshot_revision).await?;
                tx.commit().await?;
                self.revalidate_access(access).await?;
                if matches!(access, BindingAccess::Exchange(_)) && !snapshot_applied {
                    return Err(ServiceError::Conflict);
                }
                Ok(BindingView::from_row(&committed))
            }
            Err(error) => {
                let result = self
                    .handle_provider_error(
                        provider.id,
                        OPERATION_REFRESH,
                        idempotency_key,
                        &binding,
                        error,
                        Some((provider.revision, snapshot_revision)),
                    )
                    .await;
                self.revalidate_access(access).await?;
                result
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
