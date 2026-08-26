use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::users::domain::UserId;

pub const MAX_CREDIT_AMOUNT: i64 = 1_000_000_000;
pub const MAX_CREDIT_NOTE_CHARS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerKind {
    Credit,
    Purchase,
    Adjust,
}

impl LedgerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Credit => "credit",
            Self::Purchase => "purchase",
            Self::Adjust => "adjust",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletBalance {
    pub balance: i64,
    pub currency: &'static str,
}

impl WalletBalance {
    pub const fn points(balance: i64) -> Self {
        Self {
            balance,
            currency: "points",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LedgerEntry {
    pub id: i64,
    pub amount: i64,
    pub balance_after: i64,
    pub kind: String,
    pub note: Option<String>,
    pub reference_type: Option<String>,
    pub reference_id: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct PurchaseResult {
    pub balance: i64,
    pub plan_id: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    pub plan_expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreditResult {
    pub user_id: UserId,
    pub balance: i64,
}

#[derive(Debug, Deserialize)]
pub struct PurchaseInput {
    pub plan_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreditInput {
    pub amount: i64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCredit {
    pub amount: i64,
    pub note: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletError {
    #[error("credit amount must be between 1 and {MAX_CREDIT_AMOUNT}")]
    InvalidAmount,
    #[error("credit note must be at most {MAX_CREDIT_NOTE_CHARS} characters")]
    InvalidNote,
    #[error("plan id is invalid")]
    InvalidPlan,
}

pub fn validate_credit(input: CreditInput) -> Result<ValidatedCredit, WalletError> {
    if input.amount <= 0 || input.amount > MAX_CREDIT_AMOUNT {
        return Err(WalletError::InvalidAmount);
    }
    let note = input
        .note
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if note
        .as_ref()
        .is_some_and(|value| value.chars().count() > MAX_CREDIT_NOTE_CHARS)
    {
        return Err(WalletError::InvalidNote);
    }
    Ok(ValidatedCredit {
        amount: input.amount,
        note,
    })
}

pub fn validate_purchase_plan_id(plan_id: i64) -> Result<i64, WalletError> {
    if plan_id < 1 {
        return Err(WalletError::InvalidPlan);
    }
    Ok(plan_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_rejects_non_positive_and_oversized_amounts() {
        for amount in [0, -1, MAX_CREDIT_AMOUNT + 1] {
            assert_eq!(
                validate_credit(CreditInput { amount, note: None }),
                Err(WalletError::InvalidAmount)
            );
        }
        assert_eq!(
            validate_credit(CreditInput {
                amount: 1,
                note: None
            })
            .expect("min credit")
            .amount,
            1
        );
        assert_eq!(
            validate_credit(CreditInput {
                amount: MAX_CREDIT_AMOUNT,
                note: None
            })
            .expect("max credit")
            .amount,
            MAX_CREDIT_AMOUNT
        );
    }

    #[test]
    fn credit_trims_blank_note_and_rejects_overlong_note() {
        let validated = validate_credit(CreditInput {
            amount: 10,
            note: Some("  ".to_owned()),
        })
        .expect("blank note");
        assert_eq!(validated.note, None);

        let too_long = "x".repeat(MAX_CREDIT_NOTE_CHARS + 1);
        assert_eq!(
            validate_credit(CreditInput {
                amount: 10,
                note: Some(too_long)
            }),
            Err(WalletError::InvalidNote)
        );
    }

    #[test]
    fn purchase_plan_id_must_be_positive() {
        assert_eq!(validate_purchase_plan_id(0), Err(WalletError::InvalidPlan));
        assert_eq!(validate_purchase_plan_id(1), Ok(1));
    }
}
