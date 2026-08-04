use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::users::domain::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorMethod {
    Totp,
    Passkey,
}

pub fn effective_factor_methods(
    methods: impl IntoIterator<Item = String>,
    passkey_enabled: bool,
) -> Vec<FactorMethod> {
    methods
        .into_iter()
        .filter_map(|method| match method.as_str() {
            "totp" => Some(FactorMethod::Totp),
            "passkey" if passkey_enabled => Some(FactorMethod::Passkey),
            _ => None,
        })
        .collect()
}

pub fn setup_factor_methods(passkey_enabled: bool) -> Vec<FactorMethod> {
    let mut methods = vec![FactorMethod::Totp];
    if passkey_enabled {
        methods.push(FactorMethod::Passkey);
    }
    methods
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginTicket {
    pub user_id: UserId,
    methods: Vec<FactorMethod>,
    #[serde(default)]
    pub session_epoch: i64,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl LoginTicket {
    pub const TTL: Duration = Duration::minutes(5);

    pub fn new(user_id: UserId, methods: Vec<FactorMethod>) -> Self {
        Self::new_with_epoch(user_id, methods, 0)
    }

    pub fn new_with_epoch(user_id: UserId, methods: Vec<FactorMethod>, session_epoch: i64) -> Self {
        let created_at = OffsetDateTime::now_utc();
        Self {
            user_id,
            methods,
            session_epoch,
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

#[cfg(test)]
mod tests {
    use super::{FactorMethod, effective_factor_methods, setup_factor_methods};

    #[test]
    fn effective_methods_follow_passkey_policy_for_all_factor_sets() {
        let cases = [
            (
                vec!["passkey".to_owned()],
                vec![],
                vec![FactorMethod::Passkey],
            ),
            (
                vec!["totp".to_owned()],
                vec![FactorMethod::Totp],
                vec![FactorMethod::Totp],
            ),
            (
                vec!["totp".to_owned(), "passkey".to_owned()],
                vec![FactorMethod::Totp],
                vec![FactorMethod::Totp, FactorMethod::Passkey],
            ),
            (Vec::new(), vec![], vec![]),
        ];

        for (stored, disabled, enabled) in cases {
            assert_eq!(effective_factor_methods(stored.clone(), false), disabled);
            assert_eq!(effective_factor_methods(stored, true), enabled);
        }
    }

    #[test]
    fn setup_methods_never_offer_disabled_passkey() {
        assert_eq!(setup_factor_methods(false), vec![FactorMethod::Totp]);
        assert_eq!(
            setup_factor_methods(true),
            vec![FactorMethod::Totp, FactorMethod::Passkey]
        );
    }
}
