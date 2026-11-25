use serde_json::Value;
use uuid::Uuid;

use super::{LiveSnapshotWrite, Store};
use crate::resource_services::types::BindingRow;
use crate::sqlx::{Postgres, Transaction};

impl Store {
    /// 在短事务里预留查询序号。旧请求的迟到回复不得覆盖随后发起的查询结果。
    pub async fn reserve_snapshot_revision(
        tx: &mut Transaction<'_, Postgres>,
        binding_id: Uuid,
    ) -> Result<i64, crate::sqlx::Error> {
        crate::sqlx::query_scalar(
            "UPDATE resource_service_bindings
             SET snapshot_revision = snapshot_revision + 1
             WHERE id = $1 AND tombstoned_at IS NULL
             RETURNING snapshot_revision",
        )
        .bind(binding_id)
        .fetch_one(&mut **tx)
        .await
    }

    pub async fn update_observed_snapshot(
        tx: &mut Transaction<'_, Postgres>,
        write: LiveSnapshotWrite,
        snapshot_revision: i64,
        binding: &BindingRow,
    ) -> Result<Option<BindingRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "UPDATE resource_service_bindings
             SET snapshot_json = $5, updated_at = statement_timestamp()
             WHERE id = $1 AND user_id = $2 AND uid = $3
               AND tombstoned_at IS NULL AND snapshot_revision = $6
               AND grant_id IS NOT DISTINCT FROM $7
               AND EXISTS (SELECT 1 FROM resource_service_providers
                           WHERE id = resource_service_bindings.provider_id
                             AND revision = $4 AND enabled = TRUE)
             RETURNING id, provider_id, user_id, uid, issuer, grant_id,
                       grant_expires_at, generation, tombstoned_at, token_bundle_ciphertext,
                       snapshot_json, access_expires_at, refresh_expires_at, created_at, updated_at",
        )
        .bind(write.binding_id)
        .bind(write.user_id)
        .bind(&binding.uid)
        .bind(write.expected_provider_revision)
        .bind(crate::sqlx::types::Json(&write.snapshot_json))
        .bind(snapshot_revision)
        .bind(binding.grant_id)
        .fetch_optional(&mut **tx)
        .await
    }

    /// 403 没有完整快照，保留其余展示字段，只标记当前查询获知的禁用状态。
    pub async fn mark_observed_disabled(
        tx: &mut Transaction<'_, Postgres>,
        binding: &BindingRow,
        provider_revision: i64,
        snapshot_revision: i64,
    ) -> Result<bool, crate::sqlx::Error> {
        let snapshot = match binding.snapshot_json.as_object() {
            Some(object) => {
                let mut object = object.clone();
                object.insert("status".into(), Value::String("disabled".into()));
                Value::Object(object)
            }
            None => serde_json::json!({"status": "disabled"}),
        };
        Ok(Self::update_observed_snapshot(
            tx,
            LiveSnapshotWrite {
                binding_id: binding.id,
                user_id: binding.user_id,
                expected_generation: binding.generation,
                expected_provider_revision: provider_revision,
                snapshot_json: snapshot,
            },
            snapshot_revision,
            binding,
        )
        .await?
        .is_some())
    }
}
