use serde_json::Value;
use time::OffsetDateTime;

use super::{
    domain::{LedgerEntry, LedgerKind},
    idempotency::WalletIdempotencyContext,
};
use crate::sqlx::{PgPool, Postgres, Transaction};
use crate::users::domain::UserId;

const IDEMPOTENCY_TTL_SECONDS: i32 = 24 * 60 * 60;

#[derive(Debug, thiserror::Error)]
pub(crate) enum WalletIdempotencyError {
    #[error("idempotency key was already used for a different request")]
    Conflict,
    #[error("stored wallet idempotency result is invalid")]
    CorruptResult,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

pub(crate) enum WalletIdempotencyClaim {
    New,
    Replay(Value),
}

pub(crate) async fn claim_purchase(
    transaction: &mut Transaction<'_, Postgres>,
    context: &WalletIdempotencyContext,
) -> Result<WalletIdempotencyClaim, WalletIdempotencyError> {
    crate::sqlx::query(
        "DELETE FROM wallet_purchase_idempotency
         WHERE user_id = $1 AND expires_at <= NOW()",
    )
    .bind(context.user_id())
    .execute(&mut **transaction)
    .await?;

    let inserted = crate::sqlx::query(
        "INSERT INTO wallet_purchase_idempotency
            (user_id, key_digest, operation, request_hash, expires_at)
         VALUES ($1, $2, $3, $4, NOW() + make_interval(secs => $5))
         ON CONFLICT (user_id, key_digest) DO NOTHING",
    )
    .bind(context.user_id())
    .bind(context.key_digest().as_slice())
    .bind(context.operation())
    .bind(context.request_hash().as_slice())
    .bind(IDEMPOTENCY_TTL_SECONDS)
    .execute(&mut **transaction)
    .await?
    .rows_affected()
        == 1;

    let (operation, request_hash, result_data): (
        String,
        Vec<u8>,
        Option<crate::sqlx::types::Json<Value>>,
    ) = crate::sqlx::query_as(
        "SELECT operation, request_hash, result_data
             FROM wallet_purchase_idempotency
             WHERE user_id = $1 AND key_digest = $2
             FOR UPDATE",
    )
    .bind(context.user_id())
    .bind(context.key_digest().as_slice())
    .fetch_one(&mut **transaction)
    .await?;

    if operation != context.operation() || request_hash.as_slice() != context.request_hash() {
        return Err(WalletIdempotencyError::Conflict);
    }
    match (inserted, result_data) {
        (true, None) => Ok(WalletIdempotencyClaim::New),
        (false, Some(crate::sqlx::types::Json(result))) => {
            Ok(WalletIdempotencyClaim::Replay(result))
        }
        _ => Err(WalletIdempotencyError::CorruptResult),
    }
}

pub(crate) async fn complete_purchase<T: serde::Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    context: &WalletIdempotencyContext,
    result: &T,
) -> Result<(), WalletIdempotencyError> {
    let result = serde_json::to_value(result).map_err(|_| WalletIdempotencyError::CorruptResult)?;
    let updated = crate::sqlx::query(
        "UPDATE wallet_purchase_idempotency
         SET result_data = $3, completed_at = NOW()
         WHERE user_id = $1 AND key_digest = $2 AND result_data IS NULL",
    )
    .bind(context.user_id())
    .bind(context.key_digest().as_slice())
    .bind(crate::sqlx::types::Json(result))
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(WalletIdempotencyError::CorruptResult)
    }
}

type LedgerRow = (
    i64,
    i64,
    i64,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    OffsetDateTime,
);

pub async fn get_balance(pool: &PgPool, user_id: UserId) -> Result<i64, crate::sqlx::Error> {
    let balance: Option<i64> =
        crate::sqlx::query_scalar("SELECT balance FROM user_wallets WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    Ok(balance.unwrap_or(0))
}

pub async fn list_ledger(
    pool: &PgPool,
    user_id: UserId,
    limit: i64,
    offset: i64,
) -> Result<(Vec<LedgerEntry>, i64), crate::sqlx::Error> {
    let total: i64 =
        crate::sqlx::query_scalar("SELECT COUNT(id) FROM wallet_ledger WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    let rows: Vec<LedgerRow> = crate::sqlx::query_as(
        "SELECT id, amount, balance_after, kind, note, reference_type, reference_id, created_at
         FROM wallet_ledger
         WHERE user_id = $1
         ORDER BY created_at DESC, id DESC
         LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let items = rows
        .into_iter()
        .map(|row| LedgerEntry {
            id: row.0,
            amount: row.1,
            balance_after: row.2,
            kind: row.3,
            note: row.4,
            reference_type: row.5,
            reference_id: row.6,
            created_at: row.7,
        })
        .collect();
    Ok((items, total))
}

/// Insert a zero-balance wallet if missing, then lock the row.
///
/// Callers must already hold a lock that proves the user exists (user row
/// `FOR UPDATE` or the management actor/target protocol). A missing user
/// surfaces as a foreign-key violation.
pub async fn ensure_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
) -> Result<i64, crate::sqlx::Error> {
    crate::sqlx::query(
        "INSERT INTO user_wallets (user_id, balance, updated_at)
         VALUES ($1, 0, NOW())
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    crate::sqlx::query_scalar("SELECT balance FROM user_wallets WHERE user_id = $1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut **transaction)
        .await
}

pub async fn apply_delta(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
    amount: i64,
    kind: LedgerKind,
    note: Option<&str>,
    reference_type: Option<&str>,
    reference_id: Option<&str>,
) -> Result<i64, crate::sqlx::Error> {
    let balance_after: i64 = crate::sqlx::query_scalar(
        "UPDATE user_wallets
         SET balance = balance + $2, updated_at = NOW()
         WHERE user_id = $1
         RETURNING balance",
    )
    .bind(user_id)
    .bind(amount)
    .fetch_one(&mut **transaction)
    .await?;
    crate::sqlx::query(
        "INSERT INTO wallet_ledger
            (user_id, amount, balance_after, kind, note, reference_type, reference_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(user_id)
    .bind(amount)
    .bind(balance_after)
    .bind(kind.as_str())
    .bind(note)
    .bind(reference_type)
    .bind(reference_id)
    .execute(&mut **transaction)
    .await?;
    Ok(balance_after)
}

pub async fn assign_purchased_plan(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
    plan_id: i64,
    billing_period: &str,
) -> Result<Option<OffsetDateTime>, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "UPDATE users
         SET plan_id = $2,
             plan_entitlement_version = plan_entitlement_version + 1,
             plan_expires_at = CASE $3
                 WHEN 'one_time' THEN NULL
                 WHEN 'monthly' THEN NOW() + INTERVAL '30 days'
                 WHEN 'yearly' THEN NOW() + INTERVAL '365 days'
             END,
             updated_at = NOW()
         WHERE id = $1
         RETURNING plan_expires_at",
    )
    .bind(user_id)
    .bind(plan_id)
    .bind(billing_period)
    .fetch_one(&mut **transaction)
    .await
}
