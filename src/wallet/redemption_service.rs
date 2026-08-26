use thiserror::Error;

use super::{
    domain::LedgerKind,
    redemption_domain::{
        CreateRedemptionCodesInput, CreatedRedemptionCode, RedeemResult, RedemptionCodeDetail,
        RedemptionCodeSummary, digest, generate_code, validate_create,
    },
    redemption_repository, repository,
};
use crate::users::domain::UserId;
use crate::{
    audit::AuditEvent,
    sqlx::PgPool,
    users::{ManagementActorCredential, ManagementActorValidationError, domain::UserPermission},
};

#[derive(Debug, Error)]
pub enum RedemptionError {
    #[error("redemption code request is invalid")]
    InvalidInput,
    #[error("redemption code is invalid")]
    InvalidCode,
    #[error("redemption code was not found")]
    NotFound,
    #[error(transparent)]
    Audit(#[from] crate::audit::AuditError),
    #[error(transparent)]
    ManagementActor(#[from] ManagementActorValidationError),
    #[error(transparent)]
    Database(#[from] crate::sqlx::Error),
}

#[derive(Clone)]
pub struct RedemptionService {
    pool: PgPool,
}

impl RedemptionService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_batch(
        &self,
        input: CreateRedemptionCodesInput,
        actor: Option<i64>,
        credential: ManagementActorCredential,
        audit: impl FnOnce(&[CreatedRedemptionCode]) -> AuditEvent,
    ) -> Result<Vec<CreatedRedemptionCode>, RedemptionError> {
        let input = validate_create(input).map_err(|_| RedemptionError::InvalidInput)?;
        let mut tx = self.pool.begin().await?;
        crate::users::repository::management_actor::validate_management_actor_in_transaction(
            &mut tx,
            credential,
            UserPermission::ManageSettings,
        )
        .await?;
        let mut result = Vec::with_capacity(input.count as usize);
        for _ in 0..input.count {
            let code = generate_code();
            let row: redemption_repository::SummaryRow = crate::sqlx::query_as(
                "INSERT INTO wallet_redemption_codes (code_digest, label, points, max_uses, expires_at, created_by)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 RETURNING id, label, points, max_uses, use_count, expires_at, disabled_at, created_at")
                .bind(digest(&code).expect("generated code is valid").as_slice())
                .bind(&input.label).bind(input.points).bind(input.max_uses).bind(input.expires_at).bind(actor)
                .fetch_one(&mut *tx).await?;
            result.push(CreatedRedemptionCode {
                summary: redemption_repository::summary(row),
                code,
            });
        }
        crate::audit::repository::insert_with(&mut *tx, &audit(&result)).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn list(&self) -> Result<Vec<RedemptionCodeSummary>, RedemptionError> {
        Ok(redemption_repository::list(&self.pool).await?)
    }

    pub async fn detail(&self, id: i64) -> Result<RedemptionCodeDetail, RedemptionError> {
        let (summary, uses) = redemption_repository::detail(&self.pool, id)
            .await?
            .ok_or(RedemptionError::NotFound)?;
        Ok(RedemptionCodeDetail { summary, uses })
    }

    pub async fn disable(
        &self,
        id: i64,
        credential: ManagementActorCredential,
        audit: AuditEvent,
    ) -> Result<RedemptionCodeSummary, RedemptionError> {
        let mut tx = self.pool.begin().await?;
        crate::users::repository::management_actor::validate_management_actor_in_transaction(
            &mut tx,
            credential,
            UserPermission::ManageSettings,
        )
        .await?;
        let row: Option<redemption_repository::SummaryRow> = crate::sqlx::query_as(
            "UPDATE wallet_redemption_codes SET disabled_at = COALESCE(disabled_at, NOW()) WHERE id = $1
             RETURNING id, label, points, max_uses, use_count, expires_at, disabled_at, created_at")
            .bind(id).fetch_optional(&mut *tx).await?;
        let row = row.ok_or(RedemptionError::NotFound)?;
        crate::audit::repository::insert_with(&mut *tx, &audit).await?;
        tx.commit().await?;
        Ok(redemption_repository::summary(row))
    }

    pub async fn redeem(
        &self,
        user_id: UserId,
        code: &str,
        audit: AuditEvent,
    ) -> Result<RedeemResult, RedemptionError> {
        let digest = digest(code).ok_or(RedemptionError::InvalidCode)?;
        let mut tx = self.pool.begin().await?;
        if !repository::lock_user(&mut tx, user_id).await? {
            tx.rollback().await?;
            return Err(RedemptionError::InvalidCode);
        }
        let Some((code_id, points)) =
            redemption_repository::lock_redeemable(&mut tx, &digest, user_id).await?
        else {
            tx.rollback().await?;
            return Err(RedemptionError::InvalidCode);
        };
        repository::ensure_for_update(&mut tx, user_id).await?;
        let balance = repository::apply_delta(
            &mut tx,
            user_id,
            points,
            LedgerKind::Credit,
            Some("wallet redemption"),
            Some("wallet_redemption_code"),
            Some(&code_id.to_string()),
        )
        .await?;
        redemption_repository::consume(&mut tx, code_id, user_id, points).await?;
        crate::audit::repository::insert_with(&mut *tx, &audit).await?;
        tx.commit().await?;
        Ok(RedeemResult { points, balance })
    }
}
