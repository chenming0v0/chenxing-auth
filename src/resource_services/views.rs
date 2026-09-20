//! 消费方 API 的对外视图。不含密钥、令牌或密文。

use serde::Serialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
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
            grant_expires_at: row.grant_expires_at.map(rfc3339),
            access_expires_at: row.access_expires_at.map(rfc3339),
            refresh_expires_at: row.refresh_expires_at.map(rfc3339),
        }
    }
}

/// 浏览器只认 RFC3339；`OffsetDateTime::to_string()` 的 `2026-12-17 0:00:00.0 +00:00:00`
/// 会让 `new Date()` 得到 `Invalid Date`。
fn rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_services::types::BindingRow;
    use serde_json::json;
    use time::macros::datetime;

    #[test]
    fn binding_view_serializes_timestamps_as_rfc3339() {
        let now = datetime!(2026-09-19 10:00:00 UTC);
        let row = BindingRow {
            id: Uuid::nil(),
            provider_id: Uuid::nil(),
            user_id: 1,
            uid: "acct-1".to_owned(),
            issuer: "https://provider.example.com".to_owned(),
            grant_id: None,
            grant_expires_at: Some(datetime!(2026-12-17 00:00:00 UTC)),
            generation: 1,
            tombstoned_at: None,
            token_bundle_ciphertext: None,
            snapshot_json: json!({ "account": "acct-1", "name": null, "status": "active" }),
            access_expires_at: None,
            refresh_expires_at: Some(datetime!(2026-10-18 00:00:00.5 UTC)),
            created_at: now,
            updated_at: now,
        };
        let value = serde_json::to_value(BindingView::from_row(&row)).expect("json");
        assert_eq!(value["grant_expires_at"], json!("2026-12-17T00:00:00Z"));
        assert_eq!(value["access_expires_at"], Value::Null);
        assert_eq!(value["refresh_expires_at"], json!("2026-10-18T00:00:00.5Z"));
        assert_eq!(value["account"], json!("acct-1"));
        assert_eq!(value["name"], Value::Null);
    }
}
