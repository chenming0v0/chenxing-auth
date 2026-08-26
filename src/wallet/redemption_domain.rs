use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use super::domain::MAX_CREDIT_AMOUNT;

pub const MAX_BATCH_SIZE: u16 = 100;

#[derive(Debug, Deserialize)]
pub struct CreateRedemptionCodesInput {
    pub count: u16,
    pub points: i64,
    pub max_uses: i32,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RedeemCodeInput {
    pub code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedemptionCodeSummary {
    pub id: i64,
    pub label: Option<String>,
    pub points: i64,
    pub max_uses: i32,
    pub use_count: i32,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub disabled_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct CreatedRedemptionCode {
    #[serde(flatten)]
    pub summary: RedemptionCodeSummary,
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct RedemptionUse {
    pub user_id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub points: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub redeemed_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct RedemptionCodeDetail {
    #[serde(flatten)]
    pub summary: RedemptionCodeSummary,
    pub uses: Vec<RedemptionUse>,
}

#[derive(Debug, Serialize)]
pub struct RedeemResult {
    pub points: i64,
    pub balance: i64,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CreateRedemptionCodesError {
    #[error("redemption code count is invalid")]
    InvalidCount,
    #[error("redemption code points are invalid")]
    InvalidPoints,
    #[error("redemption code max uses is invalid")]
    InvalidMaxUses,
    #[error("redemption code expiration is invalid")]
    InvalidExpiration,
    #[error("redemption code label is too long")]
    InvalidLabel,
}

pub fn validate_create(
    mut input: CreateRedemptionCodesInput,
) -> Result<CreateRedemptionCodesInput, CreateRedemptionCodesError> {
    if input.count == 0 || input.count > MAX_BATCH_SIZE {
        return Err(CreateRedemptionCodesError::InvalidCount);
    }
    if !(1..=MAX_CREDIT_AMOUNT).contains(&input.points) {
        return Err(CreateRedemptionCodesError::InvalidPoints);
    }
    if !(1..=10_000).contains(&input.max_uses) {
        return Err(CreateRedemptionCodesError::InvalidMaxUses);
    }
    if input
        .expires_at
        .is_some_and(|value| value <= OffsetDateTime::now_utc())
    {
        return Err(CreateRedemptionCodesError::InvalidExpiration);
    }
    input.label = input.label.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    });
    if input
        .label
        .as_ref()
        .is_some_and(|value| value.chars().count() > 128)
    {
        return Err(CreateRedemptionCodesError::InvalidLabel);
    }
    Ok(input)
}

pub fn digest(code: &str) -> Option<[u8; 32]> {
    let code = code.trim();
    if code.len() < 16 || code.len() > 128 {
        return None;
    }
    Some(Sha256::digest(code.as_bytes()).into())
}

pub fn generate_code() -> String {
    let mut random = [0_u8; 24];
    OsRng.fill_bytes(&mut random);
    format!("cxp_{}", URL_SAFE_NO_PAD.encode(random))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_trims_but_rejects_implausible_codes() {
        let digest_a = digest("  cxp_123456789012  ").expect("valid code");
        let digest_b = digest("cxp_123456789012").expect("valid code");
        assert_eq!(digest_a, digest_b);
        assert!(digest("too-short").is_none());
        assert!(digest(&"x".repeat(129)).is_none());
    }

    #[test]
    fn generated_codes_have_a_stable_prefix_and_entropy() {
        let first = generate_code();
        let second = generate_code();
        assert!(first.starts_with("cxp_"));
        assert!(second.starts_with("cxp_"));
        assert_ne!(first, second);
    }

    #[test]
    fn creation_input_is_bounded() {
        let valid = CreateRedemptionCodesInput {
            count: 2,
            points: 100,
            max_uses: 3,
            expires_at: None,
            label: Some("  campaign  ".to_owned()),
        };
        assert_eq!(
            validate_create(valid)
                .expect("valid input")
                .label
                .as_deref(),
            Some("campaign")
        );
        assert!(
            validate_create(CreateRedemptionCodesInput {
                count: 0,
                points: 100,
                max_uses: 1,
                expires_at: None,
                label: None,
            })
            .is_err()
        );
    }
}
