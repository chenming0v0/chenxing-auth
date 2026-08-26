use time::OffsetDateTime;

use super::domain::{BillingPeriod, Plan};
use crate::sqlx::{Error as SqlxError, FromRow, PgRow, Row};

/// Named `plans` row. Extra selected columns (assigned user count, expiry,
/// add-on quotas) are read by the dedicated wrappers below so this struct
/// does not grow into another positional tuple.
pub(crate) struct PlanRow {
    pub id: i64,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub oauth_clients_limit: i32,
    pub daily_auth_limit: i64,
    pub monthly_auth_limit: Option<i64>,
    pub max_qps: Option<i32>,
    pub is_default: bool,
    pub status: String,
    pub price_points: i64,
    pub billing_period: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl PlanRow {
    pub(crate) fn into_plan(self) -> Result<Plan, SqlxError> {
        let billing_period = BillingPeriod::parse(&self.billing_period).ok_or_else(|| {
            SqlxError::Decode(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown plan billing_period {}", self.billing_period),
            )))
        })?;
        Ok(Plan {
            id: self.id,
            code: self.code,
            name: self.name,
            description: self.description,
            oauth_clients_limit: self.oauth_clients_limit,
            daily_auth_limit: self.daily_auth_limit,
            monthly_auth_limit: self.monthly_auth_limit,
            max_qps: self.max_qps,
            is_default: self.is_default,
            status: self.status,
            price_points: self.price_points,
            billing_period,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for PlanRow {
    fn from_row(row: &'r PgRow) -> Result<Self, SqlxError> {
        Ok(Self {
            id: row.try_get("id")?,
            code: row.try_get("code")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            oauth_clients_limit: row.try_get("oauth_clients_limit")?,
            daily_auth_limit: row.try_get("daily_auth_limit")?,
            monthly_auth_limit: row.try_get("monthly_auth_limit")?,
            max_qps: row.try_get("max_qps")?,
            is_default: row.try_get("is_default")?,
            status: row.try_get("status")?,
            price_points: row.try_get("price_points")?,
            billing_period: row.try_get("billing_period")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

pub(crate) struct PlanListRow {
    pub plan: Plan,
    pub assigned_users: i64,
}

impl<'r> FromRow<'r, PgRow> for PlanListRow {
    fn from_row(row: &'r PgRow) -> Result<Self, SqlxError> {
        Ok(Self {
            plan: PlanRow::from_row(row)?.into_plan()?,
            assigned_users: row.try_get("assigned_users")?,
        })
    }
}

pub(crate) struct EffectivePlanRow {
    pub plan: Plan,
    pub expires_at: Option<OffsetDateTime>,
    pub addon_daily_auth_limit: i64,
    pub addon_monthly_auth_limit: i64,
}

impl<'r> FromRow<'r, PgRow> for EffectivePlanRow {
    fn from_row(row: &'r PgRow) -> Result<Self, SqlxError> {
        Ok(Self {
            plan: PlanRow::from_row(row)?.into_plan()?,
            expires_at: row.try_get("plan_expires_at")?,
            addon_daily_auth_limit: row.try_get("addon_daily_auth_limit")?,
            addon_monthly_auth_limit: row.try_get("addon_monthly_auth_limit")?,
        })
    }
}
