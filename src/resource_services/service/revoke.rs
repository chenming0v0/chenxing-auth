use uuid::Uuid;

use crate::users::{
    UserSessionCredential, UserSessionValidation, validate_user_session_in_transaction,
};

use super::ResourceServiceService;
use crate::resource_services::service_error::ServiceError;
use crate::resource_services::store::Store;
use crate::resource_services::views::{BindingView, PublicProviderView};
use crate::users::domain::UserId;

impl ResourceServiceService {
    pub async fn unlink_binding(
        &self,
        credential: UserSessionCredential,
        binding_id: Uuid,
    ) -> Result<(), ServiceError> {
        let mut tx = self.pool.begin().await?;
        match validate_user_session_in_transaction(&mut tx, credential).await? {
            UserSessionValidation::Valid => {}
            other => return Err(ServiceError::from(other)),
        }
        let Some(binding) = Store::lock_binding(&mut tx, binding_id).await? else {
            return Err(ServiceError::BindingNotFound);
        };
        if binding.user_id != credential.user_id {
            return Err(ServiceError::BindingNotFound);
        }
        if !binding.is_live() {
            tx.commit().await?;
            return Ok(());
        }
        Store::tombstone_binding(&mut tx, binding.id, binding.generation)
            .await?
            .ok_or(ServiceError::BindingTombstoned)?;
        Store::insert_revocation_outbox(
            &mut tx,
            Uuid::new_v4(),
            binding.provider_id,
            binding.id,
            credential.user_id,
        )
        .await
        .map_err(|error| match error {
            crate::resource_services::store::StoreError::Database(error) => {
                ServiceError::from(error)
            }
            _ => ServiceError::Conflict,
        })?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_bindings(&self, user_id: UserId) -> Result<Vec<BindingView>, ServiceError> {
        Ok(self
            .store
            .list_live_bindings_for_user(user_id)
            .await?
            .iter()
            .map(BindingView::from_row)
            .collect())
    }

    pub async fn get_binding(
        &self,
        user_id: UserId,
        binding_id: Uuid,
    ) -> Result<BindingView, ServiceError> {
        let row = self
            .store
            .get_binding(binding_id)
            .await?
            .ok_or(ServiceError::BindingNotFound)?;
        if row.user_id != user_id || !row.is_live() {
            return Err(ServiceError::BindingNotFound);
        }
        Ok(BindingView::from_row(&row))
    }

    pub async fn list_public_providers(&self) -> Result<Vec<PublicProviderView>, ServiceError> {
        Ok(self
            .store
            .list_enabled_providers()
            .await?
            .iter()
            .map(PublicProviderView::from_row)
            .collect())
    }
}
