use axum::{
    Json,
    extract::{Query, State, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    domain::{PurchaseInput, WalletBalance, WalletError},
    service::WalletServiceError,
};
use crate::{
    api::extract::{ApiJson, SessionRead, SessionWrite},
    audit::AuditEvent,
    error,
    plans::domain::Plan,
    state::AppState,
};

const DEFAULT_PAGE: i64 = 1;
const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE_SIZE: i64 = 100;

#[derive(Debug, Deserialize)]
pub struct LedgerQuery {
    page: Option<String>,
    page_size: Option<String>,
}

#[derive(Debug, Serialize)]
struct PageResponse<T> {
    items: Vec<T>,
    page: i64,
    page_size: i64,
    total: i64,
}

#[derive(Debug, Serialize)]
struct CatalogPlan {
    id: i64,
    code: String,
    name: String,
    description: Option<String>,
    price_points: i64,
    billing_period: crate::plans::domain::BillingPeriod,
    oauth_clients_limit: i32,
    daily_auth_limit: i64,
    monthly_auth_limit: Option<i64>,
    max_qps: Option<i32>,
}

impl From<Plan> for CatalogPlan {
    fn from(plan: Plan) -> Self {
        Self {
            id: plan.id,
            code: plan.code,
            name: plan.name,
            description: plan.description,
            price_points: plan.price_points,
            billing_period: plan.billing_period,
            oauth_clients_limit: plan.oauth_clients_limit,
            daily_auth_limit: plan.daily_auth_limit,
            monthly_auth_limit: plan.monthly_auth_limit,
            max_qps: plan.max_qps,
        }
    }
}

pub async fn get_wallet(State(state): State<AppState>, session: SessionRead) -> Response {
    match state.wallets.balance(session.user_id).await {
        Ok(balance) => (StatusCode::OK, Json(WalletBalance::points(balance))).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load wallet balance");
            error::internal()
        }
    }
}

pub async fn list_wallet_ledger(
    State(state): State<AppState>,
    session: SessionRead,
    query: Result<Query<LedgerQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(_) => return invalid_pagination(),
    };
    let Some((page, page_size, offset)) = query.bounds() else {
        return invalid_pagination();
    };
    match state
        .wallets
        .list_ledger(session.user_id, page_size, offset)
        .await
    {
        Ok((items, total)) => (
            StatusCode::OK,
            Json(PageResponse {
                items,
                page,
                page_size,
                total,
            }),
        )
            .into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list wallet ledger");
            error::internal()
        }
    }
}

pub async fn list_plan_catalog(State(state): State<AppState>, _session: SessionRead) -> Response {
    match state.plans.list_catalog().await {
        Ok(plans) => (
            StatusCode::OK,
            Json(plans.into_iter().map(CatalogPlan::from).collect::<Vec<_>>()),
        )
            .into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list plan catalog");
            error::internal()
        }
    }
}

pub async fn purchase_plan(
    State(state): State<AppState>,
    session: SessionWrite,
    ApiJson(input): ApiJson<PurchaseInput>,
) -> Response {
    let event = AuditEvent::new(
        "user".to_owned(),
        Some(session.user_id.to_string()),
        crate::audit::AuditAction::PlanPurchase,
        "user".to_owned(),
        Some(session.user_id.to_string()),
        serde_json::json!({"result": "success"}),
    );
    match state.wallets.purchase(session.user_id, input, event).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(error_value) => wallet_error_response(error_value),
    }
}

impl LedgerQuery {
    fn bounds(&self) -> Option<(i64, i64, i64)> {
        let page = parse_positive_integer(self.page.as_deref(), DEFAULT_PAGE)?;
        let page_size = parse_positive_integer(self.page_size.as_deref(), DEFAULT_PAGE_SIZE)?;
        if page < 1 || !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return None;
        }
        let offset = page.checked_sub(1)?.checked_mul(page_size)?;
        Some((page, page_size, offset))
    }
}

fn parse_positive_integer(value: Option<&str>, default: i64) -> Option<i64> {
    match value {
        Some(value) if !value.is_empty() => value.parse().ok(),
        Some(_) => None,
        None => Some(default),
    }
}

fn invalid_pagination() -> Response {
    error::bad_request(
        "invalid_pagination",
        "page must be positive and page_size must be between 1 and 100",
    )
}

pub(crate) fn wallet_error_response(error_value: WalletServiceError) -> Response {
    match error_value {
        WalletServiceError::Validation(WalletError::InvalidAmount) => {
            error::bad_request("invalid_amount", "credit amount is invalid")
        }
        WalletServiceError::Validation(WalletError::InvalidNote) => {
            error::bad_request("invalid_note", "credit note is too long")
        }
        WalletServiceError::Validation(WalletError::InvalidPlan) => {
            error::bad_request("invalid_plan", "plan id is invalid")
        }
        WalletServiceError::InsufficientBalance => {
            error::bad_request("insufficient_balance", "wallet balance is insufficient")
        }
        WalletServiceError::PlanNotFound => {
            error::not_found("plan_not_found", "plan was not found")
        }
        WalletServiceError::PlanNotPurchasable => error::bad_request(
            "plan_not_purchasable",
            "plan is archived or not priced for self-serve purchase",
        ),
        WalletServiceError::UserNotFound => {
            error::not_found("user_not_found", "user was not found")
        }
        WalletServiceError::ActorSessionInvalid | WalletServiceError::ActorPermissionRequired => {
            tracing::error!("actor authorization outcome escaped the wallet handler");
            error::internal()
        }
        WalletServiceError::Audit(error_value) => {
            tracing::error!(error = %error_value, "wallet mutation rolled back because audit failed");
            error::service_unavailable(
                "audit_unavailable",
                "the operation was rolled back because its audit record could not be written; retry later",
            )
        }
        WalletServiceError::Database(database_error) => {
            tracing::error!(error = %database_error, "wallet database operation failed");
            error::internal()
        }
    }
}
