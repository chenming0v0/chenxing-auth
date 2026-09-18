//! 消费方 API 的对外视图。不含密钥、令牌或密文。

use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::types::{BindingRow, ProviderRow, ScopeAccess};

#[derive(Debug, Clone, Serialize)]
pub struct AdminProviderView {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub identifier_label: String,
    pub secret_label: String,
    pub identifier_sensitive: bool,
    pub scope: String,
    pub scope_description: String,
    pub scope_access: ScopeAccess,
    pub allowed_client_ids: Vec<String>,
    pub enabled: bool,
    pub revision: i64,
    pub identity_locked: bool,
}

impl AdminProviderView {
    pub fn from_row(row: &ProviderRow, identity_locked: bool) -> Self {
        Self {
            id: row.id,
            slug: row.slug.clone(),
            display_name: row.display_name.clone(),
            issuer: row.issuer.clone(),
            client_id: row.client_id.clone(),
            identifier_label: row.identifier_label.clone(),
            secret_label: row.secret_label.clone(),
            identifier_sensitive: row.identifier_sensitive,
            scope: row.scope.clone(),
            scope_description: row.scope_description.clone(),
            scope_access: row.scope_access,
            allowed_client_ids: row.allowed_client_ids.clone(),
            enabled: row.enabled,
            revision: row.revision,
            identity_locked,
        }
    }
}

/// 用户侧视图：只暴露 slug，不暴露 client_id / allowed_client_ids。
#[derive(Debug, Clone, Serialize)]
pub struct PublicProviderView {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub issuer: String,
    pub identifier_label: String,
    pub secret_label: String,
    pub identifier_sensitive: bool,
}

impl PublicProviderView {
    pub fn from_row(row: &ProviderRow) -> Self {
        Self {
            id: row.id,
            slug: row.slug.clone(),
            display_name: row.display_name.clone(),
            issuer: row.issuer.clone(),
            identifier_label: row.identifier_label.clone(),
            secret_label: row.secret_label.clone(),
            identifier_sensitive: row.identifier_sensitive,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BindingView {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub issuer: String,
    pub uid: String,
    pub account: Option<String>,
    pub name: Option<String>,
    pub status: Option<String>,
    pub snapshot: Value,
    pub grant_expires_at: Option<String>,
    pub access_expires_at: Option<String>,
    pub refresh_expires_at: Option<String>,
}

impl BindingView {
    pub fn from_row(row: &BindingRow) -> Self {
        let account = row
            .snapshot_json
            .get("account")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let name = row
            .snapshot_json
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let status = row
            .snapshot_json
            .get("status")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Self {
            id: row.id,
            provider_id: row.provider_id,
            issuer: row.issuer.clone(),
            uid: row.uid.clone(),
            account,
            name,
            status,
            snapshot: row.snapshot_json.clone(),
            grant_expires_at: row.grant_expires_at.map(|value| value.to_string()),
            access_expires_at: row.access_expires_at.map(|value| value.to_string()),
            refresh_expires_at: row.refresh_expires_at.map(|value| value.to_string()),
        }
    }
}
