//! Use cases for linked accounts.
//!
//! The public surface re-exports the browser-facing DTOs so that
//! `service::<View>` paths stay stable while those types live in `views`.

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    integrations::cltermux::{
        adapter::CltermuxIntegration,
        types::{AccountStatus, CredentialBundle, IntegrationError},
    },
    oauth::providers::service::ExternalOAuthService,
    users::domain::UserId,
};

use super::{
    error::LinkedAccountServiceError,
    provider,
    repository::{LinkedAccountInsert, LinkedAccountRepository, StoreBindingError},
    views,
};

pub use super::views::{
    AccountProviderView, CapabilityView, DisplayView, LinkedAccountView, ProviderView,
    ResolveBinding, SyncView,
};

/// 刷新冷却窗口；同时决定视图里的 `refresh_after`。
pub(super) const REFRESH_COOLDOWN: Duration = Duration::seconds(30);

#[derive(Clone)]
pub struct LinkedAccountService {
    repository: LinkedAccountRepository,
    external_oauth: ExternalOAuthService,
    cltermux: Option<CltermuxIntegration>,
    provider_settings: Option<crate::settings::SettingsService>,
}

impl LinkedAccountService {
    pub fn new(
        pool: crate::sqlx::PgPool,
        external_oauth: ExternalOAuthService,
        cltermux: Option<CltermuxIntegration>,
    ) -> Self {
        Self {
            repository: LinkedAccountRepository::new(pool),
            external_oauth,
            cltermux,
            provider_settings: None,
        }
    }

    pub fn with_provider_settings(mut self, settings: crate::settings::SettingsService) -> Self {
        self.provider_settings = Some(settings);
        self
    }

    pub async fn bind_cltermux(
        &self,
        provider_slug: &str,
        credential: crate::users::UserSessionCredential,
        credentials: CredentialBundle,
        now: OffsetDateTime,
    ) -> Result<LinkedAccountView, LinkedAccountServiceError> {
        let (integration, provider_version) =
            provider::integration(&self.cltermux, &self.provider_settings, provider_slug).await?;
        let account = integration.verify(credentials).await?;
        let id = format!("link_{}", Uuid::new_v4().simple());
        let row = match self
            .repository
            .insert_binding_for_session(
                credential,
                LinkedAccountInsert {
                    id,
                    provider_slug: provider_slug.to_owned(),
                    provider_version,
                    kind: "service_account".to_owned(),
                    uid: account.uid.clone(),
                    subject: account.subject,
                    account_status: account.account_status.as_str().to_owned(),
                    snapshot_json: crate::sqlx::types::Json(account.snapshot_json),
                    linked_at: now,
                },
            )
            .await
        {
            Ok(row) => row,
            Err(StoreBindingError::UidTaken) => {
                let Some(existing) = self
                    .repository
                    .find_binding_by_uid(provider_slug, &account.uid)
                    .await?
                else {
                    return Err(LinkedAccountServiceError::AlreadyLinked);
                };
                if existing.user_id != credential.user_id {
                    return Err(LinkedAccountServiceError::AlreadyLinked);
                }
                return views::view_from_row(existing);
            }
            Err(StoreBindingError::UserSlotTaken) => {
                return Err(LinkedAccountServiceError::AlreadyLinked);
            }
            Err(StoreBindingError::ProviderChanged) => {
                return Err(LinkedAccountServiceError::NotConfigured);
            }
            Err(StoreBindingError::SessionInvalid) => {
                return Err(LinkedAccountServiceError::SessionInvalid);
            }
            Err(StoreBindingError::UserDisabled) => {
                return Err(LinkedAccountServiceError::UserDisabled);
            }
            Err(StoreBindingError::Database(error)) => return Err(error.into()),
        };
        views::view_from_row(row)
    }

    pub async fn refresh(
        &self,
        user_id: UserId,
        binding_id: &str,
        now: OffsetDateTime,
    ) -> Result<LinkedAccountView, LinkedAccountServiceError> {
        let row = self
            .repository
            .find_binding_by_id(binding_id, user_id)
            .await?
            .ok_or(LinkedAccountServiceError::NotFound)?;
        let (integration, _) =
            provider::integration(&self.cltermux, &self.provider_settings, &row.provider_slug)
                .await?;
        if let Some(last_attempt) = row.last_attempt_at {
            let elapsed = now - last_attempt;
            if elapsed < REFRESH_COOLDOWN {
                let retry = (REFRESH_COOLDOWN - elapsed).whole_seconds().max(1) as u32;
                return Err(LinkedAccountServiceError::RateLimited {
                    retry_after_secs: retry,
                });
            }
        }
        if !self
            .repository
            .claim_refresh(binding_id, row.binding_version, now)
            .await?
        {
            return Err(LinkedAccountServiceError::NotFound);
        }
        let claimed_version = row.binding_version + 1;
        let result = integration.lookup(&row.uid).await;
        match result {
            Ok(account) if account.account_status == AccountStatus::Disabled => {
                self.repository
                    .mark_account_fact(binding_id, claimed_version, "disabled", now)
                    .await?;
                Err(IntegrationError::AccountDisabled.into())
            }
            Ok(account) if account.account_status == AccountStatus::Missing => {
                self.repository
                    .mark_account_fact(binding_id, claimed_version, "missing", now)
                    .await?;
                Err(IntegrationError::AccountNotFound.into())
            }
            Ok(account) => {
                if !self
                    .repository
                    .replace_snapshot_success(
                        binding_id,
                        claimed_version,
                        crate::sqlx::types::Json(account.snapshot_json),
                        account.account_status.as_str(),
                        now,
                    )
                    .await?
                {
                    return Err(LinkedAccountServiceError::NotFound);
                }
                let fresh = self
                    .repository
                    .find_binding_by_id(binding_id, user_id)
                    .await?
                    .ok_or(LinkedAccountServiceError::NotFound)?;
                views::view_from_row(fresh)
            }
            Err(error) => {
                if !self
                    .repository
                    .mark_sync_failure(binding_id, claimed_version, error.code(), now)
                    .await?
                {
                    return Err(LinkedAccountServiceError::NotFound);
                }
                let fresh = self
                    .repository
                    .find_binding_by_id(binding_id, user_id)
                    .await?
                    .ok_or(LinkedAccountServiceError::NotFound)?;
                if matches!(
                    &error,
                    IntegrationError::ProviderInvalidResponse
                        | IntegrationError::ProviderAuthFailed
                        | IntegrationError::ProviderUnavailable
                        | IntegrationError::ProviderTimeout
                ) && fresh.last_success_at.is_some()
                {
                    views::view_from_row(fresh)
                } else {
                    Err(error.into())
                }
            }
        }
    }

    pub async fn list(
        &self,
        user_id: UserId,
    ) -> Result<Vec<LinkedAccountView>, LinkedAccountServiceError> {
        let service_rows = self.repository.list_bindings(user_id).await?;
        let mut items = service_rows
            .into_iter()
            .map(views::view_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let oauth_rows = self.external_oauth.list_identities(user_id).await?;
        if let Some(settings) = &self.provider_settings {
            let providers = settings
                .account_providers()
                .await
                .map_err(|_| IntegrationError::ProviderUnavailable)?;
            for item in &mut items {
                if let Some(provider) = providers.iter().find(|p| p.slug == item.provider.id) {
                    item.provider.name = provider.name.clone();
                    item.capabilities.can_refresh = provider.enabled;
                }
            }
        }
        items.extend(oauth_rows.into_iter().map(views::oauth_view));
        items.sort_by(|left, right| {
            right
                .linked_at
                .cmp(&left.linked_at)
                .then_with(|| right.id.cmp(&left.id))
        });
        Ok(items)
    }

    pub async fn find(
        &self,
        user_id: UserId,
        id: &str,
    ) -> Result<LinkedAccountView, LinkedAccountServiceError> {
        let row = self
            .repository
            .find_binding_by_id(id, user_id)
            .await?
            .ok_or(LinkedAccountServiceError::NotFound)?;
        views::view_from_row(row)
    }

    pub async fn delete(&self, user_id: UserId, id: &str) -> Result<(), LinkedAccountServiceError> {
        if self.repository.delete_binding(id, user_id).await? {
            Ok(())
        } else {
            Err(LinkedAccountServiceError::NotFound)
        }
    }

    pub async fn resolve(
        &self,
        user_id: UserId,
        provider_slug: &str,
    ) -> Result<ResolveBinding, LinkedAccountServiceError> {
        let row = self
            .repository
            .find_binding_by_user_and_provider(user_id, provider_slug)
            .await?
            .ok_or(LinkedAccountServiceError::NotFound)?;
        Ok(ResolveBinding {
            uid: row.uid,
            binding_id: row.id,
            binding_version: row.binding_version,
            account_status: row.account_status,
        })
    }

    pub async fn provider_descriptors(
        &self,
    ) -> Result<Vec<AccountProviderView>, LinkedAccountServiceError> {
        provider::descriptors(&self.cltermux, &self.provider_settings).await
    }
}
