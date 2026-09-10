//! Use cases and the browser-facing aggregate for linked accounts.

use serde::Serialize;
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    integrations::cltermux::{
        adapter::CltermuxIntegration,
        types::{AccountStatus, CredentialBundle, IntegrationError},
    },
    oauth::providers::{repository::LinkedExternalIdentity, service::ExternalOAuthService},
    users::domain::UserId,
};

use super::repository::{
    LinkedAccountInsert, LinkedAccountRepository, LinkedAccountRow, StoreBindingError,
};

const PROVIDER_SLUG: &str = "cltermux";
const PROVIDER_NAME: &str = "CLtermux";
const REFRESH_COOLDOWN: Duration = Duration::seconds(30);
const SNAPSHOT_FRESHNESS: Duration = Duration::seconds(300);

#[derive(Debug, thiserror::Error)]
pub enum LinkedAccountServiceError {
    #[error("linked account was not found")]
    NotFound,
    #[error("linked account is already occupied")]
    AlreadyLinked,
    #[error("the browser session changed while binding the account")]
    SessionInvalid,
    #[error("the user account is disabled")]
    UserDisabled,
    #[error("provider is not configured")]
    NotConfigured,
    #[error("refresh is rate limited")]
    RateLimited { retry_after_secs: u32 },
    #[error("provider operation failed")]
    Integration(#[from] IntegrationError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("external identity lookup failed: {0}")]
    External(#[from] crate::oauth::providers::service::ExternalOAuthError),
    #[error("stored linked account snapshot is invalid")]
    CorruptSnapshot,
}

#[derive(Clone)]
pub struct LinkedAccountService {
    repository: LinkedAccountRepository,
    external_oauth: ExternalOAuthService,
    cltermux: Option<CltermuxIntegration>,
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
        }
    }

    pub async fn bind_cltermux(
        &self,
        credential: crate::users::UserSessionCredential,
        credentials: CredentialBundle,
        now: OffsetDateTime,
    ) -> Result<LinkedAccountView, LinkedAccountServiceError> {
        let integration = self
            .cltermux
            .as_ref()
            .ok_or(LinkedAccountServiceError::NotConfigured)?;
        let account = integration.verify(credentials).await?;
        let id = format!("link_{}", Uuid::new_v4().simple());
        let row = match self
            .repository
            .insert_binding_for_session(
                credential,
                LinkedAccountInsert {
                    id,
                    provider_slug: PROVIDER_SLUG.to_owned(),
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
                    .find_binding_by_uid(PROVIDER_SLUG, &account.uid)
                    .await?
                else {
                    return Err(LinkedAccountServiceError::AlreadyLinked);
                };
                if existing.user_id != credential.user_id {
                    return Err(LinkedAccountServiceError::AlreadyLinked);
                }
                return self.view_from_row(existing);
            }
            Err(StoreBindingError::UserSlotTaken) => {
                return Err(LinkedAccountServiceError::AlreadyLinked);
            }
            Err(StoreBindingError::SessionInvalid) => {
                return Err(LinkedAccountServiceError::SessionInvalid);
            }
            Err(StoreBindingError::UserDisabled) => {
                return Err(LinkedAccountServiceError::UserDisabled);
            }
            Err(StoreBindingError::Database(error)) => return Err(error.into()),
        };
        self.view_from_row(row)
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
        let integration = self
            .cltermux
            .as_ref()
            .ok_or(LinkedAccountServiceError::NotConfigured)?;
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
                self.view_from_row(fresh)
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
                    self.view_from_row(fresh)
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
            .map(|row| self.view_from_row(row))
            .collect::<Result<Vec<_>, _>>()?;
        let oauth_rows = self.external_oauth.list_identities(user_id).await?;
        items.extend(oauth_rows.into_iter().map(oauth_view));
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
        self.view_from_row(row)
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
    ) -> Result<ResolveBinding, LinkedAccountServiceError> {
        let row = self
            .repository
            .find_binding_by_user_and_provider(user_id, PROVIDER_SLUG)
            .await?
            .ok_or(LinkedAccountServiceError::NotFound)?;
        Ok(ResolveBinding {
            uid: row.uid,
            binding_id: row.id,
            binding_version: row.binding_version,
        })
    }

    pub fn provider_descriptors(&self) -> Vec<AccountProviderView> {
        self.cltermux
            .as_ref()
            .map(|_| {
                vec![AccountProviderView {
                    id: PROVIDER_SLUG.to_owned(),
                    name: PROVIDER_NAME.to_owned(),
                    icon_url: None,
                    kind: "service_account".to_owned(),
                    binding_method: "credentials".to_owned(),
                    can_refresh: true,
                }]
            })
            .unwrap_or_default()
    }

    fn view_from_row(
        &self,
        row: LinkedAccountRow,
    ) -> Result<LinkedAccountView, LinkedAccountServiceError> {
        let snapshot: crate::integrations::cltermux::contract::AccountSnapshotDto =
            serde_json::from_value(row.snapshot_json)
                .map_err(|_| LinkedAccountServiceError::CorruptSnapshot)?;
        Ok(LinkedAccountView {
            id: row.id,
            kind: row.kind,
            provider: ProviderView {
                id: row.provider_slug,
                name: PROVIDER_NAME.to_owned(),
                icon_url: None,
            },
            uid: Some(row.uid),
            subject_hint: None,
            display: DisplayView {
                name: snapshot.display.name,
                email: snapshot.display.email,
                avatar_url: snapshot.display.avatar_url,
            },
            account_status: row.account_status,
            linked_at: row.linked_at,
            capabilities: CapabilityView {
                can_login: false,
                can_refresh: true,
            },
            sync: SyncView {
                status: row.sync_status,
                last_attempt_at: row.last_attempt_at,
                last_success_at: row.last_success_at,
                stale_after: row.last_success_at.map(|at| at + SNAPSHOT_FRESHNESS),
                refresh_after: row.last_attempt_at.map(|at| at + REFRESH_COOLDOWN),
                error: row.sync_error,
            },
            extensions: serde_json::to_value(snapshot.extensions)
                .map_err(|_| LinkedAccountServiceError::CorruptSnapshot)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResolveBinding {
    pub uid: String,
    pub binding_id: String,
    pub binding_version: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountProviderView {
    pub id: String,
    pub name: String,
    pub icon_url: Option<String>,
    pub kind: String,
    pub binding_method: String,
    pub can_refresh: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkedAccountView {
    pub id: String,
    pub kind: String,
    pub provider: ProviderView,
    pub uid: Option<String>,
    pub subject_hint: Option<String>,
    pub display: DisplayView,
    pub account_status: String,
    #[serde(with = "time::serde::rfc3339")]
    pub linked_at: OffsetDateTime,
    pub capabilities: CapabilityView,
    pub sync: SyncView,
    pub extensions: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderView {
    pub id: String,
    pub name: String,
    pub icon_url: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct DisplayView {
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityView {
    pub can_login: bool,
    pub can_refresh: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct SyncView {
    pub status: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_attempt_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_success_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub stale_after: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub refresh_after: Option<OffsetDateTime>,
    pub error: Option<String>,
}

fn oauth_view(row: LinkedExternalIdentity) -> LinkedAccountView {
    LinkedAccountView {
        id: format!("oauth_{}", row.provider_slug),
        kind: "oauth_identity".to_owned(),
        provider: ProviderView {
            id: row.provider_slug,
            name: row.provider_name,
            icon_url: row.provider_icon,
        },
        uid: None,
        subject_hint: row.subject_hint,
        display: DisplayView {
            name: row.account_name,
            email: Some(row.email),
            avatar_url: row.avatar_url,
        },
        account_status: row.account_status.unwrap_or_else(|| "active".to_owned()),
        linked_at: row.created_at,
        capabilities: CapabilityView {
            can_login: true,
            can_refresh: false,
        },
        sync: SyncView {
            status: row.sync_status.unwrap_or_else(|| "unsupported".to_owned()),
            last_attempt_at: row.last_synced_at,
            last_success_at: row.last_synced_at,
            stale_after: None,
            refresh_after: None,
            error: row.sync_error,
        },
        extensions: row.extensions,
    }
}
