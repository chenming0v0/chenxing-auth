use thiserror::Error;

use super::{
    domain::{
        CreditInput, CreditResult, LedgerEntry, LedgerKind, PurchaseInput, PurchaseResult,
        ValidatedCredit, WalletError, validate_credit, validate_purchase_plan_id,
    },
    idempotency::WalletIdempotencyContext,
    repository,
};
use crate::audit::AuditEvent;
use crate::plans::addons::{QuotaAddonError, QuotaAddonPurchaseInput, QuotaAddonPurchaseResult};
use crate::plans::domain::Plan;
use crate::sqlx::PgPool;
use crate::users::{
    ManagementActorCredential, UserSessionCredential, UserSessionValidation,
    domain::UserId,
    repository::management_actor::{
        ManagementActorRejection, lock_management_user_advisories, lock_management_user_rows,
        validate_management_actor,
    },
    validate_user_session_in_transaction,
};

#[derive(Clone)]
pub struct WalletService {
    pool: PgPool,
}

#[derive(Debug, Error)]
pub enum WalletServiceError {
    #[error(transparent)]
    Validation(#[from] WalletError),
    #[error("wallet balance is insufficient")]
    InsufficientBalance,
    #[error("plan was not found")]
    PlanNotFound,
    #[error("plan is not purchasable")]
    PlanNotPurchasable,
    #[error("user was not found")]
    UserNotFound,
    #[error("the management actor session is no longer valid")]
    ActorSessionInvalid,
    #[error("the management actor no longer has the required permission")]
    ActorPermissionRequired,
    #[error("idempotency key was already used for a different request")]
    IdempotencyConflict,
    #[error("stored wallet idempotency result is invalid")]
    IdempotencyCorruptResult,
    #[error("the user session is no longer valid")]
    SessionInvalid,
    #[error("the user account is disabled")]
    UserDisabled,
    #[error("wallet audit operation failed: {0}")]
    Audit(#[from] crate::audit::AuditError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

impl WalletService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn balance(&self, user_id: UserId) -> Result<i64, WalletServiceError> {
        Ok(repository::get_balance(&self.pool, user_id).await?)
    }

    pub async fn list_ledger(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<LedgerEntry>, i64), WalletServiceError> {
        Ok(repository::list_ledger(&self.pool, user_id, limit, offset).await?)
    }

    pub async fn purchase(
        &self,
        credential: UserSessionCredential,
        input: PurchaseInput,
        idempotency: WalletIdempotencyContext,
        audit_event: AuditEvent,
    ) -> Result<PurchaseResult, WalletServiceError> {
        let plan_id = validate_purchase_plan_id(input.plan_id)?;
        let user_id = credential.user_id;
        let mut transaction = self.pool.begin().await?;
        match validate_user_session_in_transaction(&mut transaction, credential).await? {
            UserSessionValidation::Valid => {}
            UserSessionValidation::SessionInvalid => {
                transaction.rollback().await?;
                return Err(WalletServiceError::SessionInvalid);
            }
            UserSessionValidation::UserDisabled => {
                transaction.rollback().await?;
                return Err(WalletServiceError::UserDisabled);
            }
        }
        match repository::claim_purchase(&mut transaction, &idempotency).await {
            Ok(repository::WalletIdempotencyClaim::Replay(result)) => {
                let value = serde_json::from_value(result)
                    .map_err(|_| WalletServiceError::IdempotencyCorruptResult)?;
                transaction.rollback().await?;
                return Ok(value);
            }
            Ok(repository::WalletIdempotencyClaim::New) => {}
            Err(repository::WalletIdempotencyError::Conflict) => {
                transaction.rollback().await?;
                return Err(WalletServiceError::IdempotencyConflict);
            }
            Err(repository::WalletIdempotencyError::CorruptResult) => {
                transaction.rollback().await?;
                return Err(WalletServiceError::IdempotencyCorruptResult);
            }
            Err(repository::WalletIdempotencyError::Database(error)) => {
                transaction.rollback().await?;
                return Err(WalletServiceError::Database(error));
            }
        }
        let Some(plan) =
            crate::plans::repository::find_for_update(&mut transaction, plan_id).await?
        else {
            transaction.rollback().await?;
            return Err(WalletServiceError::PlanNotFound);
        };
        if let Err(error) = purchasable_plan(&plan) {
            transaction.rollback().await?;
            return Err(error);
        };
        let balance = repository::ensure_for_update(&mut transaction, user_id).await?;
        if balance < plan.price_points {
            transaction.rollback().await?;
            return Err(WalletServiceError::InsufficientBalance);
        }
        match validate_user_session_in_transaction(&mut transaction, credential).await? {
            UserSessionValidation::Valid => {}
            UserSessionValidation::SessionInvalid => {
                transaction.rollback().await?;
                return Err(WalletServiceError::SessionInvalid);
            }
            UserSessionValidation::UserDisabled => {
                transaction.rollback().await?;
                return Err(WalletServiceError::UserDisabled);
            }
        }
        let amount = -plan.price_points;
        let balance_after = repository::apply_delta(
            &mut transaction,
            user_id,
            amount,
            LedgerKind::Purchase,
            None,
            Some("plan"),
            Some(&plan.id.to_string()),
        )
        .await?;
        let plan_expires_at = repository::assign_purchased_plan(
            &mut transaction,
            user_id,
            plan.id,
            plan.billing_period.as_str(),
        )
        .await?;
        crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
        let result = PurchaseResult {
            balance: balance_after,
            plan_id: plan.id,
            plan_expires_at,
        };
        repository::complete_purchase(&mut transaction, &idempotency, &result)
            .await
            .map_err(map_wallet_idempotency_error)?;
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn purchase_quota_addon(
        &self,
        credential: UserSessionCredential,
        input: QuotaAddonPurchaseInput,
        idempotency: WalletIdempotencyContext,
        audit_event: AuditEvent,
    ) -> Result<QuotaAddonPurchaseResult, QuotaAddonError> {
        if input.addon_id < 1 {
            return Err(QuotaAddonError::NotFound);
        }
        let user_id = credential.user_id;
        let mut transaction = self.pool.begin().await?;
        match validate_user_session_in_transaction(&mut transaction, credential).await? {
            UserSessionValidation::Valid => {}
            UserSessionValidation::SessionInvalid => {
                transaction.rollback().await?;
                return Err(QuotaAddonError::SessionInvalid);
            }
            UserSessionValidation::UserDisabled => {
                transaction.rollback().await?;
                return Err(QuotaAddonError::UserDisabled);
            }
        }
        match repository::claim_purchase(&mut transaction, &idempotency).await {
            Ok(repository::WalletIdempotencyClaim::Replay(result)) => {
                let value = serde_json::from_value(result)
                    .map_err(|_| QuotaAddonError::IdempotencyCorruptResult)?;
                transaction.rollback().await?;
                return Ok(value);
            }
            Ok(repository::WalletIdempotencyClaim::New) => {}
            Err(repository::WalletIdempotencyError::Conflict) => {
                transaction.rollback().await?;
                return Err(QuotaAddonError::IdempotencyConflict);
            }
            Err(repository::WalletIdempotencyError::CorruptResult) => {
                transaction.rollback().await?;
                return Err(QuotaAddonError::IdempotencyCorruptResult);
            }
            Err(repository::WalletIdempotencyError::Database(error)) => {
                transaction.rollback().await?;
                return Err(QuotaAddonError::Database(error));
            }
        }
        let plan: Option<(i64, time::OffsetDateTime, i64)> = crate::sqlx::query_as(
            "SELECT plan_id, plan_expires_at, plan_entitlement_version FROM users
             WHERE id=$1 AND plan_id IS NOT NULL AND plan_expires_at > NOW()
             FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((plan_id, expires_at, plan_entitlement_version)) = plan else {
            transaction.rollback().await?;
            return Err(QuotaAddonError::NoActivePlan);
        };
        let Some(plan) =
            crate::plans::repository::find_for_update(&mut transaction, plan_id).await?
        else {
            transaction.rollback().await?;
            return Err(QuotaAddonError::NoActivePlan);
        };
        if plan.status != "active"
            || !matches!(
                plan.billing_period,
                crate::plans::domain::BillingPeriod::Monthly
                    | crate::plans::domain::BillingPeriod::Yearly
            )
        {
            transaction.rollback().await?;
            return Err(QuotaAddonError::NoActivePlan);
        }
        let Some(addon) =
            crate::plans::addons::lock_active(&mut transaction, input.addon_id, plan_id).await?
        else {
            transaction.rollback().await?;
            return Err(QuotaAddonError::NotAvailable);
        };
        let balance = repository::ensure_for_update(&mut transaction, user_id).await?;
        if balance < addon.price_points {
            transaction.rollback().await?;
            return Err(QuotaAddonError::InsufficientBalance);
        }
        match validate_user_session_in_transaction(&mut transaction, credential).await? {
            UserSessionValidation::Valid => {}
            UserSessionValidation::SessionInvalid => {
                transaction.rollback().await?;
                return Err(QuotaAddonError::SessionInvalid);
            }
            UserSessionValidation::UserDisabled => {
                transaction.rollback().await?;
                return Err(QuotaAddonError::UserDisabled);
            }
        }
        let purchase_id = crate::plans::addons::grant(
            &mut transaction,
            user_id,
            &addon,
            plan_entitlement_version,
            Some(expires_at),
        )
        .await?;
        let balance = repository::apply_delta(
            &mut transaction,
            user_id,
            -addon.price_points,
            LedgerKind::Purchase,
            None,
            Some("quota_addon_purchase"),
            Some(&purchase_id.to_string()),
        )
        .await?;
        crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
        let result = QuotaAddonPurchaseResult {
            balance,
            addon_id: addon.id,
            plan_expires_at: Some(expires_at),
        };
        repository::complete_purchase(&mut transaction, &idempotency, &result)
            .await
            .map_err(map_quota_addon_idempotency_error)?;
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn credit(
        &self,
        user_id: UserId,
        input: CreditInput,
        credential: ManagementActorCredential,
        audit_event: AuditEvent,
    ) -> Result<CreditResult, WalletServiceError> {
        let ValidatedCredit { amount, note } = validate_credit(input)?;
        let mut transaction = self.pool.begin().await?;
        let lock_order =
            lock_management_user_advisories(&mut transaction, user_id, credential).await?;
        let locked = lock_management_user_rows(&mut transaction, &lock_order).await?;
        match validate_management_actor(credential, &locked) {
            Ok(_) => {}
            Err(ManagementActorRejection::SessionInvalid) => {
                transaction.rollback().await?;
                return Err(WalletServiceError::ActorSessionInvalid);
            }
            Err(ManagementActorRejection::PermissionRequired) => {
                transaction.rollback().await?;
                return Err(WalletServiceError::ActorPermissionRequired);
            }
        }
        if locked.target.is_none() {
            transaction.rollback().await?;
            return Err(WalletServiceError::UserNotFound);
        }
        repository::ensure_for_update(&mut transaction, user_id).await?;
        let balance = repository::apply_delta(
            &mut transaction,
            user_id,
            amount,
            LedgerKind::Credit,
            note.as_deref(),
            None,
            None,
        )
        .await?;
        crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
        transaction.commit().await?;
        Ok(CreditResult { user_id, balance })
    }
}

fn purchasable_plan(plan: &Plan) -> Result<(), WalletServiceError> {
    if plan.status != "active" || plan.price_points <= 0 {
        return Err(WalletServiceError::PlanNotPurchasable);
    }
    Ok(())
}

fn map_wallet_idempotency_error(error: repository::WalletIdempotencyError) -> WalletServiceError {
    match error {
        repository::WalletIdempotencyError::Conflict => WalletServiceError::IdempotencyConflict,
        repository::WalletIdempotencyError::CorruptResult => {
            WalletServiceError::IdempotencyCorruptResult
        }
        repository::WalletIdempotencyError::Database(error) => WalletServiceError::Database(error),
    }
}

fn map_quota_addon_idempotency_error(error: repository::WalletIdempotencyError) -> QuotaAddonError {
    match error {
        repository::WalletIdempotencyError::Conflict => QuotaAddonError::IdempotencyConflict,
        repository::WalletIdempotencyError::CorruptResult => {
            QuotaAddonError::IdempotencyCorruptResult
        }
        repository::WalletIdempotencyError::Database(error) => QuotaAddonError::Database(error),
    }
}
