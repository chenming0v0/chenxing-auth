//! 操作 lease 与撤销 outbox。HTTP 调用提供方期间不持有这些行的锁。

use uuid::Uuid;

use super::{OPERATION_PKEY, OUTBOX_BINDING_UNIQUE, StoreError, unique_violation};
use crate::account_portal::types::{OPERATION_LEASE, OperationRow, OutboxRow};
use crate::sqlx::{Postgres, Transaction};
use crate::users::domain::UserId;

#[derive(Clone)]
pub struct OperationLease {
    pub idempotency_key: Uuid,
    pub provider_id: Uuid,
    pub binding_id: Uuid,
    pub user_id: UserId,
    pub operation_type: String,
    pub request_fingerprint: String,
    pub provider_revision: i64,
}

pub enum ClaimedOperation {
    Created(OperationRow),
    Existing(OperationRow),
}

impl super::Store {
    pub async fn claim_operation(
        tx: &mut Transaction<'_, Postgres>,
        lease: OperationLease,
    ) -> Result<ClaimedOperation, StoreError> {
        let created: Option<OperationRow> = crate::sqlx::query_as(
            "INSERT INTO account_portal_operations (
                 idempotency_key, provider_id, binding_id, user_id,
                 operation_type, status, lease_until, request_fingerprint, provider_revision
             ) VALUES (
                 $1, $2, $3, $4, $5, 'leased',
                 statement_timestamp() + MAKE_INTERVAL(secs => $6),
                 $7, $8
             )
             ON CONFLICT ON CONSTRAINT account_portal_operations_pkey DO NOTHING
             RETURNING idempotency_key, provider_id, binding_id, user_id, operation_type,
                       status, lease_until, request_fingerprint, provider_revision,
                       created_at, committed_at",
        )
        .bind(lease.idempotency_key)
        .bind(lease.provider_id)
        .bind(lease.binding_id)
        .bind(lease.user_id)
        .bind(&lease.operation_type)
        .bind(OPERATION_LEASE.whole_seconds() as i32)
        .bind(&lease.request_fingerprint)
        .bind(lease.provider_revision)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| {
            if unique_violation(&error, OPERATION_PKEY) {
                StoreError::Conflict
            } else {
                StoreError::Database(error)
            }
        })?;
        if let Some(row) = created {
            return Ok(ClaimedOperation::Created(row));
        }
        let existing = crate::sqlx::query_as(
            "SELECT idempotency_key, provider_id, binding_id, user_id, operation_type,
                    status, lease_until, request_fingerprint, provider_revision,
                    created_at, committed_at
             FROM account_portal_operations
             WHERE provider_id = $1 AND operation_type = $2 AND idempotency_key = $3
             FOR UPDATE",
        )
        .bind(lease.provider_id)
        .bind(&lease.operation_type)
        .bind(lease.idempotency_key)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(StoreError::Conflict)?;
        Ok(ClaimedOperation::Existing(existing))
    }

    pub async fn reclaim_expired_lease(
        tx: &mut Transaction<'_, Postgres>,
        lease: &OperationLease,
    ) -> Result<Option<OperationRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "UPDATE account_portal_operations
             SET status = 'leased',
                 lease_until = statement_timestamp() + MAKE_INTERVAL(secs => $5)
             WHERE provider_id = $1
               AND operation_type = $2
               AND idempotency_key = $3
               AND request_fingerprint = $4
               AND binding_id = $6
               AND status = 'leased'
               AND (lease_until IS NULL OR lease_until <= statement_timestamp())
             RETURNING idempotency_key, provider_id, binding_id, user_id, operation_type,
                       status, lease_until, request_fingerprint, provider_revision,
                       created_at, committed_at",
        )
        .bind(lease.provider_id)
        .bind(&lease.operation_type)
        .bind(lease.idempotency_key)
        .bind(&lease.request_fingerprint)
        .bind(OPERATION_LEASE.whole_seconds() as i32)
        .bind(lease.binding_id)
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn mark_operation_committed(
        tx: &mut Transaction<'_, Postgres>,
        provider_id: Uuid,
        operation_type: &str,
        idempotency_key: Uuid,
    ) -> Result<Option<OperationRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "UPDATE account_portal_operations
             SET status = 'committed',
                 committed_at = statement_timestamp(),
                 lease_until = NULL
             WHERE provider_id = $1
               AND operation_type = $2
               AND idempotency_key = $3
               AND status = 'leased'
             RETURNING idempotency_key, provider_id, binding_id, user_id, operation_type,
                       status, lease_until, request_fingerprint, provider_revision,
                       created_at, committed_at",
        )
        .bind(provider_id)
        .bind(operation_type)
        .bind(idempotency_key)
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn mark_operation_failed(
        tx: &mut Transaction<'_, Postgres>,
        provider_id: Uuid,
        operation_type: &str,
        idempotency_key: Uuid,
    ) -> Result<Option<OperationRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "UPDATE account_portal_operations
             SET status = 'failed',
                 lease_until = NULL
             WHERE provider_id = $1
               AND operation_type = $2
               AND idempotency_key = $3
               AND status = 'leased'
             RETURNING idempotency_key, provider_id, binding_id, user_id, operation_type,
                       status, lease_until, request_fingerprint, provider_revision,
                       created_at, committed_at",
        )
        .bind(provider_id)
        .bind(operation_type)
        .bind(idempotency_key)
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn insert_revocation_outbox(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        provider_id: Uuid,
        binding_id: Uuid,
        user_id: UserId,
    ) -> Result<OutboxRow, StoreError> {
        let inserted: Option<OutboxRow> = crate::sqlx::query_as(
            "INSERT INTO account_portal_revocation_outbox (
                 id, provider_id, binding_id, user_id
             ) VALUES ($1, $2, $3, $4)
             ON CONFLICT ON CONSTRAINT account_portal_revocation_outbox_binding_key DO NOTHING
             RETURNING id, provider_id, binding_id, user_id, attempts,
                       available_at, processed_at, last_error, created_at",
        )
        .bind(id)
        .bind(provider_id)
        .bind(binding_id)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| {
            if unique_violation(&error, OUTBOX_BINDING_UNIQUE) {
                StoreError::Conflict
            } else {
                StoreError::Database(error)
            }
        })?;
        if let Some(row) = inserted {
            return Ok(row);
        }
        crate::sqlx::query_as(
            "SELECT id, provider_id, binding_id, user_id, attempts,
                    available_at, processed_at, last_error, created_at
             FROM account_portal_revocation_outbox
             WHERE binding_id = $1
             FOR UPDATE",
        )
        .bind(binding_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(StoreError::Conflict)
    }

    pub async fn claim_revocation_outbox(
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<OutboxRow>, crate::sqlx::Error> {
        crate::sqlx::query_as(
            "WITH next AS (
                 SELECT id
                 FROM account_portal_revocation_outbox
                 WHERE processed_at IS NULL
                   AND available_at <= statement_timestamp()
                 ORDER BY available_at ASC, id ASC
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             UPDATE account_portal_revocation_outbox AS outbox
             SET attempts = outbox.attempts + 1,
                 available_at = statement_timestamp()
                     + MAKE_INTERVAL(secs => LEAST(300, 30 * (outbox.attempts + 1)))
             FROM next
             WHERE outbox.id = next.id
             RETURNING outbox.id, outbox.provider_id, outbox.binding_id, outbox.user_id,
                       outbox.attempts, outbox.available_at, outbox.processed_at,
                       outbox.last_error, outbox.created_at",
        )
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn mark_outbox_processed(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<bool, crate::sqlx::Error> {
        let updated = crate::sqlx::query(
            "UPDATE account_portal_revocation_outbox
             SET processed_at = statement_timestamp(),
                 last_error = NULL
             WHERE id = $1 AND processed_at IS NULL",
        )
        .bind(id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        Ok(updated == 1)
    }

    pub async fn record_outbox_error(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        error: &str,
    ) -> Result<(), crate::sqlx::Error> {
        let message = if error.len() > 512 {
            &error[..512]
        } else {
            error
        };
        crate::sqlx::query(
            "UPDATE account_portal_revocation_outbox
             SET last_error = $2
             WHERE id = $1 AND processed_at IS NULL",
        )
        .bind(id)
        .bind(message)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}
