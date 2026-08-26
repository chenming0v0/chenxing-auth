use thiserror::Error;

use super::{
    domain::{
        CreditInput, CreditResult, LedgerEntry, LedgerKind, PurchaseInput, PurchaseResult,
        ValidatedCredit, WalletError, validate_credit, validate_purchase_plan_id,
    },
    repository,
};
use crate::audit::AuditEvent;
use crate::plans::addons::{QuotaAddonError, QuotaAddonPurchaseInput, QuotaAddonPurchaseResult};
use crate::plans::domain::Plan;
use crate::sqlx::PgPool;
use crate::users::{
    ManagementActorCredential,
    domain::UserId,
    repository::management_actor::{
        ManagementActorRejection, lock_management_user_advisories, lock_management_user_rows,
        validate_management_actor,
    },
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
        user_id: UserId,
        input: PurchaseInput,
        audit_event: AuditEvent,
    ) -> Result<PurchaseResult, WalletServiceError> {
        let plan_id = validate_purchase_plan_id(input.plan_id)?;
        let mut transaction = self.pool.begin().await?;
        if !repository::lock_user(&mut transaction, user_id).await? {
            transaction.rollback().await?;
            return Err(WalletServiceError::UserNotFound);
        };
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
        transaction.commit().await?;
        Ok(PurchaseResult {
            balance: balance_after,
            plan_id: plan.id,
            plan_expires_at,
        })
    }

    pub async fn purchase_quota_addon(
        &self,
        user_id: UserId,
        input: QuotaAddonPurchaseInput,
        audit_event: AuditEvent,
    ) -> Result<QuotaAddonPurchaseResult, QuotaAddonError> {
        if input.addon_id < 1 {
            return Err(QuotaAddonError::NotFound);
        }
        let mut transaction = self.pool.begin().await?;
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
        transaction.commit().await?;
        Ok(QuotaAddonPurchaseResult {
            balance,
            addon_id: addon.id,
            plan_expires_at: Some(expires_at),
        })
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
