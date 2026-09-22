//! 提供方配置行。身份字段在有未完成绑定 / 操作 / outbox 时由调用方拒绝修改。

use uuid::Uuid;

use super::{ISSUER_UNIQUE, SCOPE_UNIQUE, SLUG_UNIQUE, StoreError, unique_violation};
use crate::resource_services::types::{ProviderRow, ScopeAccess, provider_identity_locked};
use crate::sqlx::{Postgres, Transaction};

pub const MAX_PROVIDERS: i64 = 100;

pub struct ProviderWrite {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret_ciphertext: String,
    pub identifier_label: String,
    pub secret_label: String,
    pub identifier_sensitive: bool,
    pub scope: String,
    pub scope_description: String,
    pub scope_access: ScopeAccess,
    pub allowed_client_ids: Vec<String>,
    pub enabled: bool,
}

/// slug / scope / issuer 三个唯一键的冲突映射；其余错误原样透传。
fn map_unique_violation(error: crate::sqlx::Error) -> StoreError {
    if unique_violation(&error, ISSUER_UNIQUE) {
        StoreError::IssuerTaken
    } else if unique_violation(&error, SLUG_UNIQUE) {
        StoreError::SlugTaken
    } else if unique_violation(&error, SCOPE_UNIQUE) {
        StoreError::ScopeTaken
    } else {
        StoreError::Database(error)
    }
}

pub struct IdentityLockCounts {
    pub live_bindings: i64,
    pub leased_operations: i64,
    pub pending_outbox: i64,
}

impl IdentityLockCounts {
    pub fn is_locked(&self) -> bool {
        provider_identity_locked(
            self.live_bindings,
            self.leased_operations,
            self.pending_outbox,
        )
    }
}

impl super::Store {
    pub async fn list_providers(&self) -> Result<Vec<ProviderRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "SELECT id, slug, display_name, issuer, client_id, client_secret_ciphertext,
                    identifier_label, secret_label, identifier_sensitive,
                    scope, scope_description, scope_access, allowed_client_ids, enabled,
                    revision, created_at, updated_at
             FROM resource_service_providers
             ORDER BY created_at ASC, id ASC",
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn list_enabled_providers(&self) -> Result<Vec<ProviderRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "SELECT id, slug, display_name, issuer, client_id, client_secret_ciphertext,
                    identifier_label, secret_label, identifier_sensitive,
                    scope, scope_description, scope_access, allowed_client_ids, enabled,
                    revision, created_at, updated_at
             FROM resource_service_providers
             WHERE enabled = TRUE
             ORDER BY created_at ASC, id ASC",
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_provider(&self, id: Uuid) -> Result<Option<ProviderRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "SELECT id, slug, display_name, issuer, client_id, client_secret_ciphertext,
                    identifier_label, secret_label, identifier_sensitive,
                    scope, scope_description, scope_access, allowed_client_ids, enabled,
                    revision, created_at, updated_at
             FROM resource_service_providers
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    /// 不加锁读 revision。终态快照写入要对齐 `update_live_snapshot`，但不能在已锁绑定行时再锁提供方。
    pub async fn provider_revision(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<i64>, crate::sqlx::Error> {
        crate::sqlx::query_scalar("SELECT revision FROM resource_service_providers WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
    }

    pub async fn lock_provider(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<ProviderRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "SELECT id, slug, display_name, issuer, client_id, client_secret_ciphertext,
                    identifier_label, secret_label, identifier_sensitive,
                    scope, scope_description, scope_access, allowed_client_ids, enabled,
                    revision, created_at, updated_at
             FROM resource_service_providers
             WHERE id = $1
             FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn identity_lock_counts(
        tx: &mut Transaction<'_, Postgres>,
        provider_id: Uuid,
    ) -> Result<IdentityLockCounts, crate::sqlx::Error> {
        let (live_bindings, leased_operations, pending_outbox) = crate::sqlx::query_as(
            "SELECT
                (SELECT COUNT(*) FROM resource_service_bindings
                  WHERE provider_id = $1 AND tombstoned_at IS NULL),
                (SELECT COUNT(*) FROM resource_service_operations
                  WHERE provider_id = $1
                    AND status = 'leased'
                    AND (lease_until IS NULL OR lease_until > statement_timestamp())),
                (SELECT COUNT(*) FROM resource_service_revocation_outbox
                  WHERE provider_id = $1 AND processed_at IS NULL)",
        )
        .bind(provider_id)
        .fetch_one(&mut **tx)
        .await?;
        Ok(IdentityLockCounts {
            live_bindings,
            leased_operations,
            pending_outbox,
        })
    }

    pub async fn insert_provider(
        tx: &mut Transaction<'_, Postgres>,
        write: ProviderWrite,
    ) -> Result<ProviderRow, StoreError> {
        let inserted: Option<ProviderRow> = crate::sqlx::query_as(
            "INSERT INTO resource_service_providers (
                 id, slug, display_name, issuer, client_id, client_secret_ciphertext,
                 identifier_label, secret_label, identifier_sensitive,
                 scope, scope_description, scope_access, allowed_client_ids, enabled
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
             ON CONFLICT ON CONSTRAINT resource_service_providers_issuer_key DO NOTHING
             RETURNING id, slug, display_name, issuer, client_id, client_secret_ciphertext,
                       identifier_label, secret_label, identifier_sensitive,
                       scope, scope_description, scope_access, allowed_client_ids, enabled,
                       revision, created_at, updated_at",
        )
        .bind(write.id)
        .bind(&write.slug)
        .bind(&write.display_name)
        .bind(&write.issuer)
        .bind(&write.client_id)
        .bind(&write.client_secret_ciphertext)
        .bind(&write.identifier_label)
        .bind(&write.secret_label)
        .bind(write.identifier_sensitive)
        .bind(&write.scope)
        .bind(&write.scope_description)
        .bind(write.scope_access.as_str())
        .bind(&write.allowed_client_ids)
        .bind(write.enabled)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_unique_violation)?;
        inserted.ok_or(StoreError::IssuerTaken)
    }

    pub async fn update_provider(
        tx: &mut Transaction<'_, Postgres>,
        expected_revision: i64,
        write: ProviderWrite,
    ) -> Result<ProviderRow, StoreError> {
        crate::sqlx::query("SAVEPOINT resource_service_update_provider")
            .execute(&mut **tx)
            .await?;
        let updated: Result<Option<ProviderRow>, crate::sqlx::Error> = crate::sqlx::query_as(
            "UPDATE resource_service_providers
             SET display_name = $3,
                 issuer = $4,
                 client_id = $5,
                 client_secret_ciphertext = $6,
                 identifier_label = $7,
                 secret_label = $8,
                 identifier_sensitive = $9,
                 enabled = $10,
                 slug = $11,
                 scope = $12,
                 scope_description = $13,
                 scope_access = $14,
                 allowed_client_ids = $15,
                 revision = revision + 1,
                 updated_at = statement_timestamp()
             WHERE id = $1 AND revision = $2
             RETURNING id, slug, display_name, issuer, client_id, client_secret_ciphertext,
                       identifier_label, secret_label, identifier_sensitive,
                       scope, scope_description, scope_access, allowed_client_ids, enabled,
                       revision, created_at, updated_at",
        )
        .bind(write.id)
        .bind(expected_revision)
        .bind(&write.display_name)
        .bind(&write.issuer)
        .bind(&write.client_id)
        .bind(&write.client_secret_ciphertext)
        .bind(&write.identifier_label)
        .bind(&write.secret_label)
        .bind(write.identifier_sensitive)
        .bind(write.enabled)
        .bind(&write.slug)
        .bind(&write.scope)
        .bind(&write.scope_description)
        .bind(write.scope_access.as_str())
        .bind(&write.allowed_client_ids)
        .fetch_optional(&mut **tx)
        .await;
        match updated {
            Ok(Some(row)) => {
                crate::sqlx::query("RELEASE SAVEPOINT resource_service_update_provider")
                    .execute(&mut **tx)
                    .await?;
                Ok(row)
            }
            Ok(None) => {
                crate::sqlx::query("RELEASE SAVEPOINT resource_service_update_provider")
                    .execute(&mut **tx)
                    .await?;
                Err(StoreError::Conflict)
            }
            Err(error) => {
                crate::sqlx::query("ROLLBACK TO SAVEPOINT resource_service_update_provider")
                    .execute(&mut **tx)
                    .await?;
                Err(map_unique_violation(error))
            }
        }
    }

    pub async fn set_provider_enabled(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        enabled: bool,
    ) -> Result<Option<ProviderRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "UPDATE resource_service_providers
             SET enabled = $2,
                 revision = revision + 1,
                 updated_at = statement_timestamp()
             WHERE id = $1
             RETURNING id, slug, display_name, issuer, client_id, client_secret_ciphertext,
                       identifier_label, secret_label, identifier_sensitive,
                       scope, scope_description, scope_access, allowed_client_ids, enabled,
                       revision, created_at, updated_at",
        )
        .bind(id)
        .bind(enabled)
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn count_providers(
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<i64, crate::sqlx::Error> {
        crate::sqlx::query_scalar("SELECT COUNT(*) FROM resource_service_providers")
            .fetch_one(&mut **tx)
            .await
    }
}
