//! Account Provider v1 消费方 SQL 出口。只碰 0058/0059 的四张资源服务表。

use crate::sqlx::{PgPool, PgRow, Row};
use serde_json::Value;
use uuid::Uuid;

use super::types::{BindingRow, OperationRow, OutboxRow, ProviderRow, ScopeAccess};
use crate::users::domain::UserId;

mod binding;
mod operation;
mod provider;

pub use binding::*;
pub use operation::*;
pub use provider::*;

pub const ISSUER_UNIQUE: &str = "resource_service_providers_issuer_key";
pub const SLUG_UNIQUE: &str = "resource_service_providers_slug_key";
pub const SCOPE_UNIQUE: &str = "resource_service_providers_scope_key";
pub const LIVE_PROVIDER_USER: &str = "resource_service_bindings_live_provider_user";
pub const LIVE_PROVIDER_UID: &str = "resource_service_bindings_live_provider_uid";
pub const OPERATION_PKEY: &str = "resource_service_operations_pkey";
pub const OUTBOX_BINDING_UNIQUE: &str = "resource_service_revocation_outbox_binding_key";

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("resource service issuer is already registered")]
    IssuerTaken,
    #[error("resource service slug is already registered")]
    SlugTaken,
    #[error("resource service scope is already declared by another service")]
    ScopeTaken,
    #[error("resource service user already has a live binding on this provider")]
    UserSlotTaken,
    #[error("resource service uid is already bound on this provider")]
    UidTaken,
    #[error("resource service row was changed concurrently")]
    Conflict,
    #[error("resource service database operation failed")]
    Database(#[from] crate::sqlx::Error),
}

/// 缺钥且已有密文时必须 fail closed。禁用提供方、tombstone 绑定只要还留着密文，
/// 都算「已有密文」。操作行与 outbox 不存可逆密文，不参与判定。
pub async fn has_persisted_ciphertext(pool: &PgPool) -> Result<bool, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM resource_service_providers
             WHERE octet_length(client_secret_ciphertext) > 0
         ) OR EXISTS (
             SELECT 1 FROM resource_service_bindings
             WHERE token_bundle_ciphertext IS NOT NULL
               AND octet_length(token_bundle_ciphertext) > 0
         )",
    )
    .fetch_one(pool)
    .await
}

pub fn operation_fingerprint(
    operation_type: &str,
    provider_id: Uuid,
    binding_id: Uuid,
    user_id: UserId,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(operation_type.as_bytes());
    hasher.update([0]);
    hasher.update(provider_id.as_bytes());
    hasher.update(binding_id.as_bytes());
    hasher.update(user_id.to_be_bytes());
    format!("{:x}", hasher.finalize())
}

pub(crate) fn unique_violation(error: &crate::sqlx::Error, constraint: &str) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.constraint())
        .is_some_and(|name| name == constraint)
}

impl<'r> crate::sqlx::FromRow<'r, PgRow> for ProviderRow {
    fn from_row(row: &'r PgRow) -> Result<Self, crate::sqlx::Error> {
        let scope_access: String = row.try_get("scope_access")?;
        let scope_access = scope_access.parse::<ScopeAccess>().map_err(|error| {
            crate::sqlx::Error::ColumnDecode {
                index: "scope_access".to_owned(),
                source: Box::new(error),
            }
        })?;
        Ok(Self {
            id: row.try_get("id")?,
            slug: row.try_get("slug")?,
            display_name: row.try_get("display_name")?,
            issuer: row.try_get("issuer")?,
            client_id: row.try_get("client_id")?,
            client_secret_ciphertext: row.try_get("client_secret_ciphertext")?,
            identifier_label: row.try_get("identifier_label")?,
            secret_label: row.try_get("secret_label")?,
            identifier_sensitive: row.try_get("identifier_sensitive")?,
            scope: row.try_get("scope")?,
            scope_description: row.try_get("scope_description")?,
            scope_access,
            allowed_client_ids: row.try_get("allowed_client_ids")?,
            enabled: row.try_get("enabled")?,
            revision: row.try_get("revision")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> crate::sqlx::FromRow<'r, PgRow> for BindingRow {
    fn from_row(row: &'r PgRow) -> Result<Self, crate::sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            provider_id: row.try_get("provider_id")?,
            user_id: row.try_get("user_id")?,
            uid: row.try_get("uid")?,
            issuer: row.try_get("issuer")?,
            grant_id: row.try_get("grant_id")?,
            grant_expires_at: row.try_get("grant_expires_at")?,
            generation: row.try_get("generation")?,
            tombstoned_at: row.try_get("tombstoned_at")?,
            token_bundle_ciphertext: row.try_get("token_bundle_ciphertext")?,
            snapshot_json: row
                .try_get::<crate::sqlx::types::Json<Value>, _>("snapshot_json")?
                .0,
            access_expires_at: row.try_get("access_expires_at")?,
            refresh_expires_at: row.try_get("refresh_expires_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> crate::sqlx::FromRow<'r, PgRow> for OperationRow {
    fn from_row(row: &'r PgRow) -> Result<Self, crate::sqlx::Error> {
        Ok(Self {
            idempotency_key: row.try_get("idempotency_key")?,
            provider_id: row.try_get("provider_id")?,
            binding_id: row.try_get("binding_id")?,
            user_id: row.try_get("user_id")?,
            operation_type: row.try_get("operation_type")?,
            status: row.try_get("status")?,
            lease_until: row.try_get("lease_until")?,
            request_fingerprint: row.try_get("request_fingerprint")?,
            provider_revision: row.try_get("provider_revision")?,
            created_at: row.try_get("created_at")?,
            committed_at: row.try_get("committed_at")?,
        })
    }
}

impl<'r> crate::sqlx::FromRow<'r, PgRow> for OutboxRow {
    fn from_row(row: &'r PgRow) -> Result<Self, crate::sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            provider_id: row.try_get("provider_id")?,
            binding_id: row.try_get("binding_id")?,
            user_id: row.try_get("user_id")?,
            attempts: row.try_get("attempts")?,
            available_at: row.try_get("available_at")?,
            processed_at: row.try_get("processed_at")?,
            last_error: row.try_get("last_error")?,
            created_at: row.try_get("created_at")?,
        })
    }
}
