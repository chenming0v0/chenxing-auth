use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use super::domain::{MAX_DAILY_AUTH_LIMIT, MAX_MONTHLY_AUTH_LIMIT};
use crate::sqlx::{PgPool, Postgres, Transaction};
use crate::users::{
    ManagementActorCredential,
    domain::{UserId, UserPermission},
};

type AddonRow = (
    i64,
    i64,
    String,
    String,
    Option<String>,
    i64,
    i64,
    i64,
    String,
    OffsetDateTime,
    OffsetDateTime,
);

fn from_row(row: AddonRow) -> QuotaAddon {
    QuotaAddon {
        id: row.0,
        plan_id: row.1,
        code: row.2,
        name: row.3,
        description: row.4,
        price_points: row.5,
        daily_auth_limit: row.6,
        monthly_auth_limit: row.7,
        status: row.8,
        created_at: row.9,
        updated_at: row.10,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QuotaAddon {
    pub id: i64,
    pub plan_id: i64,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub price_points: i64,
    pub daily_auth_limit: i64,
    pub monthly_auth_limit: i64,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, Clone)]
pub struct QuotaAddonInput {
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub price_points: i64,
    pub daily_auth_limit: i64,
    pub monthly_auth_limit: i64,
}

#[derive(Debug, Deserialize)]
pub struct QuotaAddonPurchaseInput {
    pub addon_id: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuotaAddonPurchaseResult {
    pub balance: i64,
    pub addon_id: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    pub plan_expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Error)]
pub enum QuotaAddonError {
    #[error("addon code is invalid")]
    InvalidCode,
    #[error("addon name is invalid")]
    InvalidName,
    #[error("addon description is too long")]
    InvalidDescription,
    #[error("addon values are invalid")]
    InvalidValues,
    #[error("quota add-on was not found")]
    NotFound,
    #[error("quota add-on code already exists for this plan")]
    CodeConflict,
    #[error("quota add-on is not available for the active plan")]
    NotAvailable,
    #[error("wallet balance is insufficient")]
    InsufficientBalance,
    #[error("user has no active purchased plan period")]
    NoActivePlan,
    #[error("idempotency key was already used for a different request")]
    IdempotencyConflict,
    #[error("stored wallet idempotency result is invalid")]
    IdempotencyCorruptResult,
    #[error(transparent)]
    ManagementActor(#[from] crate::users::ManagementActorValidationError),
    #[error(transparent)]
    Audit(#[from] crate::audit::AuditError),
    #[error(transparent)]
    Database(#[from] crate::sqlx::Error),
}

pub fn validate_input(input: QuotaAddonInput) -> Result<QuotaAddonInput, QuotaAddonError> {
    let code = input.code.trim().to_ascii_lowercase();
    if code.is_empty()
        || code.len() > 64
        || !code
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(QuotaAddonError::InvalidCode);
    }
    let name = input.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 128 {
        return Err(QuotaAddonError::InvalidName);
    }
    let description = input
        .description
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty());
    if description
        .as_ref()
        .is_some_and(|v| v.chars().count() > 512)
    {
        return Err(QuotaAddonError::InvalidDescription);
    }
    if input.price_points <= 0
        || !(0..=MAX_DAILY_AUTH_LIMIT).contains(&input.daily_auth_limit)
        || !(0..=MAX_MONTHLY_AUTH_LIMIT).contains(&input.monthly_auth_limit)
    {
        return Err(QuotaAddonError::InvalidValues);
    }
    Ok(QuotaAddonInput {
        code,
        name,
        description,
        ..input
    })
}

pub async fn list_for_plan(
    pool: &PgPool,
    plan_id: i64,
    active_only: bool,
) -> Result<Vec<QuotaAddon>, crate::sqlx::Error> {
    let rows: Vec<AddonRow> = crate::sqlx::query_as(
        "SELECT id, plan_id, code, name, description, price_points, daily_auth_limit,
                monthly_auth_limit, status, created_at, updated_at
         FROM plan_quota_addons WHERE plan_id = $1 AND (NOT $2 OR status = 'active') ORDER BY id",
    )
    .bind(plan_id)
    .bind(active_only)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(from_row).collect())
}

pub async fn create(
    pool: &PgPool,
    plan_id: i64,
    input: QuotaAddonInput,
    credential: ManagementActorCredential,
    audit: crate::audit::AuditEvent,
) -> Result<QuotaAddon, QuotaAddonError> {
    let input = validate_input(input)?;
    let mut tx = pool.begin().await?;
    crate::users::repository::management_actor::validate_management_actor_in_transaction(
        &mut tx,
        credential,
        UserPermission::ManageSettings,
    )
    .await?;
    let exists: bool =
        crate::sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM plans WHERE id = $1)")
            .bind(plan_id)
            .fetch_one(&mut *tx)
            .await?;
    if !exists {
        tx.rollback().await?;
        return Err(QuotaAddonError::NotFound);
    }
    let row: AddonRow = crate::sqlx::query_as(
        "INSERT INTO plan_quota_addons (plan_id, code, name, description, price_points, daily_auth_limit, monthly_auth_limit)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, plan_id, code, name, description, price_points,
         daily_auth_limit, monthly_auth_limit, status, created_at, updated_at"
    ).bind(plan_id).bind(&input.code).bind(&input.name).bind(&input.description).bind(input.price_points)
     .bind(input.daily_auth_limit).bind(input.monthly_auth_limit).fetch_one(&mut *tx).await.map_err(map_conflict)?;
    crate::audit::repository::insert_with(&mut *tx, &audit).await?;
    tx.commit().await?;
    Ok(from_row(row))
}

pub async fn update(
    pool: &PgPool,
    id: i64,
    input: QuotaAddonInput,
    credential: ManagementActorCredential,
    audit: crate::audit::AuditEvent,
) -> Result<QuotaAddon, QuotaAddonError> {
    let input = validate_input(input)?;
    let mut tx = pool.begin().await?;
    crate::users::repository::management_actor::validate_management_actor_in_transaction(
        &mut tx,
        credential,
        UserPermission::ManageSettings,
    )
    .await?;
    let row: Option<AddonRow> = crate::sqlx::query_as(
        "UPDATE plan_quota_addons SET code=$2,name=$3,description=$4,price_points=$5,daily_auth_limit=$6,
         monthly_auth_limit=$7,updated_at=NOW() WHERE id=$1 RETURNING id,plan_id,code,name,description,
         price_points,daily_auth_limit,monthly_auth_limit,status,created_at,updated_at"
    ).bind(id).bind(&input.code).bind(&input.name).bind(&input.description).bind(input.price_points)
     .bind(input.daily_auth_limit).bind(input.monthly_auth_limit).fetch_optional(&mut *tx).await.map_err(map_conflict)?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Err(QuotaAddonError::NotFound);
    };
    crate::audit::repository::insert_with(&mut *tx, &audit).await?;
    tx.commit().await?;
    Ok(from_row(row))
}

pub async fn archive(
    pool: &PgPool,
    id: i64,
    credential: ManagementActorCredential,
    audit: crate::audit::AuditEvent,
) -> Result<(), QuotaAddonError> {
    let mut tx = pool.begin().await?;
    crate::users::repository::management_actor::validate_management_actor_in_transaction(
        &mut tx,
        credential,
        UserPermission::ManageSettings,
    )
    .await?;
    let affected = crate::sqlx::query(
        "UPDATE plan_quota_addons SET status='archived',updated_at=NOW() WHERE id=$1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if affected == 0 {
        tx.rollback().await?;
        return Err(QuotaAddonError::NotFound);
    }
    crate::audit::repository::insert_with(&mut *tx, &audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn lock_active(
    transaction: &mut Transaction<'_, Postgres>,
    addon_id: i64,
    plan_id: i64,
) -> Result<Option<QuotaAddon>, crate::sqlx::Error> {
    let row: Option<AddonRow> = crate::sqlx::query_as(
        "SELECT id,plan_id,code,name,description,price_points,daily_auth_limit,monthly_auth_limit,status,created_at,updated_at
         FROM plan_quota_addons WHERE id=$1 AND plan_id=$2 AND status='active' FOR UPDATE"
    ).bind(addon_id).bind(plan_id).fetch_optional(&mut **transaction).await?;
    Ok(row.map(from_row))
}

pub async fn grant(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
    addon: &QuotaAddon,
    plan_entitlement_version: i64,
    expires_at: Option<OffsetDateTime>,
) -> Result<i64, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "INSERT INTO user_quota_addon_purchases (user_id,plan_id,addon_id,plan_entitlement_version,daily_auth_limit,monthly_auth_limit,plan_expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id"
    ).bind(user_id).bind(addon.plan_id).bind(addon.id).bind(plan_entitlement_version)
     .bind(addon.daily_auth_limit).bind(addon.monthly_auth_limit).bind(expires_at).fetch_one(&mut **transaction).await
}

fn map_conflict(error: crate::sqlx::Error) -> QuotaAddonError {
    if error
        .as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|c| c == "23505")
    {
        QuotaAddonError::CodeConflict
    } else {
        QuotaAddonError::Database(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_catalog_input() {
        let input = QuotaAddonInput {
            code: " Extra-1 ".into(),
            name: " Extra ".into(),
            description: Some(" ".into()),
            price_points: 1,
            daily_auth_limit: 10,
            monthly_auth_limit: 20,
        };
        let value = validate_input(input).expect("valid addon");
        assert_eq!(value.code, "extra-1");
        assert_eq!(value.name, "Extra");
        assert_eq!(value.description, None);
    }
    #[test]
    fn rejects_free_or_negative_addons() {
        let input = QuotaAddonInput {
            code: "x".into(),
            name: "X".into(),
            description: None,
            price_points: 0,
            daily_auth_limit: 1,
            monthly_auth_limit: 1,
        };
        assert!(matches!(
            validate_input(input),
            Err(QuotaAddonError::InvalidValues)
        ));
    }
}
