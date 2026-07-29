use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::users::domain::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorMethod {
    Totp,
    Passkey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginTicket {
    pub user_id: UserId,
    methods: Vec<FactorMethod>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl LoginTicket {
    pub const TTL: Duration = Duration::minutes(5);

    pub fn new(user_id: UserId, methods: Vec<FactorMethod>) -> Self {
        let created_at = OffsetDateTime::now_utc();
        Self {
            user_id,
            methods,
            created_at,
            expires_at: created_at + Self::TTL,
        }
    }

    pub fn methods(&self) -> &[FactorMethod] {
        &self.methods
    }

    pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
        now < self.expires_at
    }

    pub fn supports(&self, method: FactorMethod) -> bool {
        self.methods.contains(&method)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TotpCodeError {
    #[error("TOTP code must contain exactly six ASCII digits")]
    InvalidFormat,
}

pub fn validate_totp_code(code: &str) -> Result<(), TotpCodeError> {
    (code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()))
        .then_some(())
        .ok_or(TotpCodeError::InvalidFormat)
}
