//! Browser-facing view DTOs for the linked-accounts aggregate.
//!
//! Projecting repository rows and OAuth identities into these DTOs lives here
//! so that `service.rs` stays focused on use-case orchestration.

use serde::Serialize;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::oauth::providers::repository::LinkedExternalIdentity;

use super::{
    error::LinkedAccountServiceError, provider::PROVIDER_NAME, repository::LinkedAccountRow,
    service::REFRESH_COOLDOWN,
};

const SNAPSHOT_FRESHNESS: Duration = Duration::seconds(300);

#[derive(Debug, Clone)]
pub struct ResolveBinding {
    pub uid: String,
    pub binding_id: String,
    pub binding_version: i32,
    /// 绑定的账号事实状态，由兑换端点判定 disabled / missing（Issue #709）。
    pub account_status: String,
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

pub(super) fn view_from_row(
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

pub(super) fn oauth_view(row: LinkedExternalIdentity) -> LinkedAccountView {
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
