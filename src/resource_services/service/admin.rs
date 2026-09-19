use uuid::Uuid;

use crate::audit::{AuditEvent, AuditService};
use crate::users::{
    ManagementActorCredential, domain::UserPermission,
    repository::management_actor::validate_management_actor_in_transaction,
};

use super::ResourceServiceService;
use super::scope_input::ScopeDeclaration;
use crate::resource_services::client::AccountProviderClient;
use crate::resource_services::metadata::ProviderMetadata;
use crate::resource_services::secret::SecretString;
use crate::resource_services::service_error::ServiceError;
use crate::resource_services::store::{self, Store, StoreError};
use crate::resource_services::types::ScopeAccess;
use crate::resource_services::views::AdminProviderView;

pub struct ProviderWrite {
    pub slug: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// `None` / 空串时缺省为 `<slug>:access`。
    pub scope: Option<String>,
    pub scope_description: String,
    pub scope_access: ScopeAccess,
    pub allowed_client_ids: Vec<String>,
    pub expected_revision: i64,
}

impl ProviderWrite {
    fn scope_declaration(&self) -> Result<ScopeDeclaration, ServiceError> {
        ScopeDeclaration::validate(
            self.slug.clone(),
            self.scope.clone(),
            self.scope_description.clone(),
            self.scope_access,
            self.allowed_client_ids.clone(),
        )
    }
}

impl ResourceServiceService {
    pub async fn list_admin_providers(&self) -> Result<Vec<AdminProviderView>, ServiceError> {
        let rows = self.store.list_providers().await?;
        let mut views = Vec::with_capacity(rows.len());
        for row in rows {
            let locked = self.provider_is_locked(row.id).await?;
            views.push(AdminProviderView::from_row(&row, locked));
        }
        Ok(views)
    }

    pub async fn get_admin_provider(
        &self,
        id: Uuid,
    ) -> Result<Option<AdminProviderView>, ServiceError> {
        let Some(row) = self.store.get_provider(id).await? else {
            return Ok(None);
        };
        let locked = self.provider_is_locked(id).await?;
        Ok(Some(AdminProviderView::from_row(&row, locked)))
    }

    pub async fn create_provider(
        &self,
        input: ProviderWrite,
        _audit: &AuditService,
        credential: ManagementActorCredential,
        event: AuditEvent,
    ) -> Result<AdminProviderView, ServiceError> {
        let issuer = crate::resource_services::scalar::Issuer::parse(&input.issuer)
            .map_err(|_| ServiceError::InvalidInput("issuer"))?;
        validate_display_name(&input.display_name)?;
        validate_client_id(&input.client_id)?;
        let declaration = input.scope_declaration()?;
        let secret = input
            .client_secret
            .filter(|value| !value.is_empty())
            .ok_or(ServiceError::InvalidInput("client_secret"))?;
        if secret.len() < 32 || secret.len() > 512 {
            return Err(ServiceError::InvalidInput("client_secret"));
        }
        let id = Uuid::new_v4();
        let secret = SecretString::new(secret);
        let metadata = self
            .fetch_metadata(&issuer, &input.client_id, &secret)
            .await?;
        let ciphertext = self.encrypt_provider_secret(id, &secret)?;
        let mut tx = self.pool.begin().await?;
        validate_management_actor_in_transaction(
            &mut tx,
            credential,
            UserPermission::ManageIdentityProviders,
        )
        .await
        .map_err(|_| ServiceError::Unavailable)?;
        if Store::count_providers(&mut tx).await? >= store::MAX_PROVIDERS {
            return Err(ServiceError::Conflict);
        }
        let inserted = Store::insert_provider(
            &mut tx,
            store::ProviderWrite {
                id,
                slug: declaration.slug,
                display_name: input.display_name,
                issuer: issuer.as_str().to_owned(),
                client_id: input.client_id,
                client_secret_ciphertext: ciphertext,
                identifier_label: metadata.credentials.identifier_label,
                secret_label: metadata.credentials.secret_label,
                identifier_sensitive: metadata.credentials.identifier_sensitive,
                scope: declaration.scope,
                scope_description: declaration.scope_description,
                scope_access: declaration.scope_access,
                allowed_client_ids: declaration.allowed_client_ids,
                enabled: true,
            },
        )
        .await
        .map_err(map_store)?;
        crate::audit::repository::insert_with(&mut *tx, &event)
            .await
            .map_err(|_| ServiceError::AuditUnavailable)?;
        tx.commit().await?;
        Ok(AdminProviderView::from_row(&inserted, false))
    }

    pub async fn update_provider(
        &self,
        id: Uuid,
        input: ProviderWrite,
        _audit: &AuditService,
        credential: ManagementActorCredential,
        event: AuditEvent,
    ) -> Result<AdminProviderView, ServiceError> {
        let issuer = crate::resource_services::scalar::Issuer::parse(&input.issuer)
            .map_err(|_| ServiceError::InvalidInput("issuer"))?;
        validate_display_name(&input.display_name)?;
        validate_client_id(&input.client_id)?;
        let declaration = input.scope_declaration()?;
        let mut tx = self.pool.begin().await?;
        validate_management_actor_in_transaction(
            &mut tx,
            credential,
            UserPermission::ManageIdentityProviders,
        )
        .await
        .map_err(|_| ServiceError::Unavailable)?;
        let Some(current) = Store::lock_provider(&mut tx, id).await? else {
            return Err(ServiceError::ProviderNotFound);
        };
        if current.revision != input.expected_revision {
            return Err(ServiceError::Conflict);
        }
        let counts = Store::identity_lock_counts(&mut tx, id).await?;
        let locked = counts.is_locked();
        if locked && (current.issuer != issuer.as_str() || current.client_id != input.client_id) {
            return Err(ServiceError::IdentityLocked);
        }
        let ciphertext = if let Some(secret) = input.client_secret.filter(|value| !value.is_empty())
        {
            if secret.len() < 32 || secret.len() > 512 {
                return Err(ServiceError::InvalidInput("client_secret"));
            }
            self.encrypt_provider_secret(id, &SecretString::new(secret))?
        } else {
            current.client_secret_ciphertext.clone()
        };
        let mut next = current.clone();
        next.issuer = issuer.as_str().to_owned();
        next.client_id = input.client_id.clone();
        next.client_secret_ciphertext = ciphertext.clone();
        let secret = self.decrypt_provider_secret(&next)?;
        let metadata = self
            .fetch_metadata(&issuer, &input.client_id, &secret)
            .await?;
        let updated = Store::update_provider(
            &mut tx,
            input.expected_revision,
            store::ProviderWrite {
                id,
                slug: declaration.slug,
                display_name: input.display_name,
                issuer: issuer.as_str().to_owned(),
                client_id: input.client_id,
                client_secret_ciphertext: ciphertext,
                identifier_label: metadata.credentials.identifier_label,
                secret_label: metadata.credentials.secret_label,
                identifier_sensitive: metadata.credentials.identifier_sensitive,
                scope: declaration.scope,
                scope_description: declaration.scope_description,
                scope_access: declaration.scope_access,
                allowed_client_ids: declaration.allowed_client_ids,
                enabled: current.enabled,
            },
        )
        .await
        .map_err(map_store)?;
        crate::audit::repository::insert_with(&mut *tx, &event)
            .await
            .map_err(|_| ServiceError::AuditUnavailable)?;
        tx.commit().await?;
        Ok(AdminProviderView::from_row(&updated, locked))
    }

    pub async fn set_provider_enabled(
        &self,
        id: Uuid,
        enabled: bool,
        _audit: &AuditService,
        credential: ManagementActorCredential,
        event: AuditEvent,
    ) -> Result<AdminProviderView, ServiceError> {
        let mut tx = self.pool.begin().await?;
        validate_management_actor_in_transaction(
            &mut tx,
            credential,
            UserPermission::ManageIdentityProviders,
        )
        .await
        .map_err(|_| ServiceError::Unavailable)?;
        let Some(updated) = Store::set_provider_enabled(&mut tx, id, enabled).await? else {
            return Err(ServiceError::ProviderNotFound);
        };
        crate::audit::repository::insert_with(&mut *tx, &event)
            .await
            .map_err(|_| ServiceError::AuditUnavailable)?;
        tx.commit().await?;
        let locked = self.provider_is_locked(id).await?;
        Ok(AdminProviderView::from_row(&updated, locked))
    }

    async fn provider_is_locked(&self, id: Uuid) -> Result<bool, ServiceError> {
        let mut tx = self.pool.begin().await?;
        let counts = Store::identity_lock_counts(&mut tx, id).await?;
        tx.commit().await?;
        Ok(counts.is_locked())
    }

    async fn fetch_metadata(
        &self,
        issuer: &crate::resource_services::scalar::Issuer,
        client_id: &str,
        secret: &SecretString,
    ) -> Result<ProviderMetadata, ServiceError> {
        let client = AccountProviderClient::new(
            self.transport.clone(),
            issuer.clone(),
            client_id.to_owned(),
            secret.clone(),
        )
        .map_err(ServiceError::Protocol)?;
        client.metadata().await.map_err(ServiceError::from)
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

fn validate_display_name(value: &str) -> Result<(), ServiceError> {
    if value.is_empty() || value.len() > 128 {
        return Err(ServiceError::InvalidInput("display_name"));
    }
    Ok(())
}

fn validate_client_id(value: &str) -> Result<(), ServiceError> {
    if value.is_empty() || value.len() > 512 || value.contains(':') {
        return Err(ServiceError::InvalidInput("client_id"));
    }
    Ok(())
}
