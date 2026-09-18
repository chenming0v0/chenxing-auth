//! 绑定行。解绑是 tombstone，不是 DELETE；延迟创建不能复活同一 UUID。

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{LIVE_PROVIDER_UID, LIVE_PROVIDER_USER, StoreError, unique_violation};
use crate::account_portal::types::BindingRow;
use crate::sqlx::{Postgres, Transaction};
use crate::users::domain::UserId;

pub struct PendingBinding {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub user_id: UserId,
    pub issuer: String,
}

pub struct CommittedBundle {
    pub binding_id: Uuid,
    pub expected_generation: i64,
    pub uid: String,
    pub grant_id: Uuid,
    pub grant_expires_at: OffsetDateTime,
    pub token_bundle_ciphertext: String,
    pub snapshot_json: Value,
    pub access_expires_at: OffsetDateTime,
    pub refresh_expires_at: OffsetDateTime,
}

impl super::Store {
    pub async fn lock_live_binding_for_user(
        tx: &mut Transaction<'_, Postgres>,
        provider_id: Uuid,
        user_id: UserId,
    ) -> Result<Option<BindingRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "SELECT id, provider_id, user_id, uid, issuer, grant_id,
                    grant_expires_at, generation, tombstoned_at, token_bundle_ciphertext,
                    snapshot_json, access_expires_at, refresh_expires_at, created_at, updated_at
             FROM account_portal_bindings
             WHERE provider_id = $1 AND user_id = $2 AND tombstoned_at IS NULL
             FOR UPDATE",
        )
        .bind(provider_id)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn lock_binding(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<BindingRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "SELECT id, provider_id, user_id, uid, issuer, grant_id,
                    grant_expires_at, generation, tombstoned_at, token_bundle_ciphertext,
                    snapshot_json, access_expires_at, refresh_expires_at, created_at, updated_at
             FROM account_portal_bindings
             WHERE id = $1
             FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn get_binding(&self, id: Uuid) -> Result<Option<BindingRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "SELECT id, provider_id, user_id, uid, issuer, grant_id,
                    grant_expires_at, generation, tombstoned_at, token_bundle_ciphertext,
                    snapshot_json, access_expires_at, refresh_expires_at, created_at, updated_at
             FROM account_portal_bindings
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn list_live_bindings_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<BindingRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "SELECT id, provider_id, user_id, uid, issuer, grant_id,
                    grant_expires_at, generation, tombstoned_at, token_bundle_ciphertext,
                    snapshot_json, access_expires_at, refresh_expires_at, created_at, updated_at
             FROM account_portal_bindings
             WHERE user_id = $1 AND tombstoned_at IS NULL
             ORDER BY created_at ASC, id ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn insert_pending_binding(
        tx: &mut Transaction<'_, Postgres>,
        pending: PendingBinding,
    ) -> Result<BindingRow, StoreError> {
        let inserted: Option<BindingRow> = crate::sqlx::query_as(
            "INSERT INTO account_portal_bindings (
                 id, provider_id, user_id, uid, issuer, snapshot_json
             ) VALUES ($1, $2, $3, '', $4, '{}'::jsonb)
             ON CONFLICT (provider_id, user_id) WHERE tombstoned_at IS NULL
             DO NOTHING
             RETURNING id, provider_id, user_id, uid, issuer, grant_id,
                       grant_expires_at, generation, tombstoned_at, token_bundle_ciphertext,
                       snapshot_json, access_expires_at, refresh_expires_at, created_at, updated_at",
        )
        .bind(pending.id)
        .bind(pending.provider_id)
        .bind(pending.user_id)
        .bind(&pending.issuer)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| {
            if unique_violation(&error, LIVE_PROVIDER_USER) {
                StoreError::UserSlotTaken
            } else {
                StoreError::Database(error)
            }
        })?;
        inserted.ok_or(StoreError::UserSlotTaken)
    }

    pub async fn commit_created_binding(
        tx: &mut Transaction<'_, Postgres>,
        bundle: CommittedBundle,
    ) -> Result<BindingRow, StoreError> {
        commit_bundle(tx, bundle, true).await
    }

    pub async fn commit_refreshed_binding(
        tx: &mut Transaction<'_, Postgres>,
        bundle: CommittedBundle,
    ) -> Result<BindingRow, StoreError> {
        commit_bundle(tx, bundle, false).await
    }

    pub async fn tombstone_binding(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        expected_generation: i64,
    ) -> Result<Option<BindingRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "UPDATE account_portal_bindings
             SET tombstoned_at = statement_timestamp(),
                 token_bundle_ciphertext = NULL,
                 generation = generation + 1,
                 updated_at = statement_timestamp()
             WHERE id = $1
               AND tombstoned_at IS NULL
               AND generation = $2
             RETURNING id, provider_id, user_id, uid, issuer, grant_id,
                       grant_expires_at, generation, tombstoned_at, token_bundle_ciphertext,
                       snapshot_json, access_expires_at, refresh_expires_at, created_at, updated_at",
        )
        .bind(id)
        .bind(expected_generation)
        .fetch_optional(&mut **tx)
        .await
    }
}

async fn commit_bundle(
    tx: &mut Transaction<'_, Postgres>,
    bundle: CommittedBundle,
    creating: bool,
) -> Result<BindingRow, StoreError> {
    crate::sqlx::query("SAVEPOINT account_portal_commit_bundle")
        .execute(&mut **tx)
        .await?;
    let updated: Result<Option<BindingRow>, crate::sqlx::Error> = crate::sqlx::query_as(
        "UPDATE account_portal_bindings
         SET uid = $3,
             grant_id = $4,
             grant_expires_at = $5,
             token_bundle_ciphertext = $6,
             snapshot_json = $7,
             access_expires_at = $8,
             refresh_expires_at = $9,
             generation = generation + 1,
             updated_at = statement_timestamp()
         WHERE id = $1
           AND tombstoned_at IS NULL
           AND generation = $2
           AND (
                ($10 AND uid = '')
                OR (NOT $10 AND uid = $3 AND grant_id = $4 AND grant_expires_at = $5)
           )
         RETURNING id, provider_id, user_id, uid, issuer, grant_id,
                   grant_expires_at, generation, tombstoned_at, token_bundle_ciphertext,
                   snapshot_json, access_expires_at, refresh_expires_at, created_at, updated_at",
    )
    .bind(bundle.binding_id)
    .bind(bundle.expected_generation)
    .bind(&bundle.uid)
    .bind(bundle.grant_id)
    .bind(bundle.grant_expires_at)
    .bind(&bundle.token_bundle_ciphertext)
    .bind(crate::sqlx::types::Json(&bundle.snapshot_json))
    .bind(bundle.access_expires_at)
    .bind(bundle.refresh_expires_at)
    .bind(creating)
    .fetch_optional(&mut **tx)
    .await;
    match updated {
        Ok(Some(row)) => {
            crate::sqlx::query("RELEASE SAVEPOINT account_portal_commit_bundle")
                .execute(&mut **tx)
                .await?;
            Ok(row)
        }
        Ok(None) => {
            crate::sqlx::query("RELEASE SAVEPOINT account_portal_commit_bundle")
                .execute(&mut **tx)
                .await?;
            Err(StoreError::Conflict)
        }
        Err(error) if unique_violation(&error, LIVE_PROVIDER_UID) => {
            crate::sqlx::query("ROLLBACK TO SAVEPOINT account_portal_commit_bundle")
                .execute(&mut **tx)
                .await?;
            Err(StoreError::UidTaken)
        }
        Err(error) => {
            crate::sqlx::query("ROLLBACK TO SAVEPOINT account_portal_commit_bundle")
                .execute(&mut **tx)
                .await?;
            Err(StoreError::Database(error))
        }
    }
}
