//! Product-bound login assertions, never OAuth access tokens or business sessions.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    keys::KeyManager,
    oauth::token::{AccessTokenClaims, TokenError, encode_claims},
    resource_services::types::BindingRow,
};

use super::support::ExchangeInput;

pub(super) const LOGIN_SCOPE: &str = "cltermux:access";
pub(super) const LIFETIME_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppKind {
    ChromeTermux,
    TermuxChrome,
}

impl AppKind {
    /// 协议线上的产品标识，只接受精确小写值，不接受别名或大小写变体。
    pub(super) fn from_wire(value: &str) -> Option<Self> {
        match value {
            "chrome_termux" => Some(Self::ChromeTermux),
            "termux_chrome" => Some(Self::TermuxChrome),
            _ => None,
        }
    }

    /// The package comes only from the active OAuth Client's Owner-managed
    /// Android Asset Link declaration, never a request field or second registry.
    pub(super) fn from_package(package: &str) -> Option<Self> {
        match package {
            "top.clyact" => Some(Self::ChromeTermux),
            "com.termux" => Some(Self::TermuxChrome),
            _ => None,
        }
    }
}

/// `cltermux:` plus a positive decimal integer of at most 18 digits.
/// Leading zeros are rejected. 18 matches the Go verifier bound.
pub(super) fn valid_uid(uid: &str) -> bool {
    let Some(id) = uid.strip_prefix("cltermux:") else {
        return false;
    };
    let mut bytes = id.bytes();
    matches!(bytes.next(), Some(b'1'..=b'9'))
        && bytes.len() <= 17
        && bytes.all(|byte| byte.is_ascii_digit())
}

#[derive(Serialize)]
struct LoginTicketClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    v: u8,
    token_use: &'a str,
    uid: &'a str,
    binding_id: String,
    binding_version: i64,
    scope: &'a str,
    app_kind: AppKind,
    device_id: &'a str,
    iat: i64,
    exp: i64,
}

pub(super) fn issue(
    keys: &KeyManager,
    access: &AccessTokenClaims,
    binding: &BindingRow,
    input: &ExchangeInput,
    now: OffsetDateTime,
) -> Result<String, TokenError> {
    let iat = now.unix_timestamp();
    let exp = iat
        .checked_add(LIFETIME_SECONDS)
        .filter(|_| iat >= 0)
        .ok_or(TokenError::InvalidLifetime)?;
    encode_claims(
        keys,
        &LoginTicketClaims {
            iss: &access.iss,
            aud: &access.aud,
            sub: &access.sub,
            v: 2,
            token_use: "cltermux_login",
            uid: &binding.uid,
            binding_id: binding.id.to_string(),
            binding_version: binding.generation,
            scope: LOGIN_SCOPE,
            app_kind: input.app_kind,
            device_id: &input.device_id,
            iat,
            exp,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_registered_product_packages_map_to_apps() {
        assert_eq!(
            AppKind::from_package("top.clyact"),
            Some(AppKind::ChromeTermux)
        );
        assert_eq!(
            AppKind::from_package("com.termux"),
            Some(AppKind::TermuxChrome)
        );
        for package in [
            "",
            "TOP.CLYACT",
            "top.clyact ",
            "com.other",
            "com.termux.extra",
        ] {
            assert_eq!(AppKind::from_package(package), None);
        }
    }

    #[test]
    fn uid_must_be_a_positive_cltermux_account() {
        assert!(valid_uid("cltermux:42"));
        for uid in [
            "cltermux:0",
            "cltermux:-1",
            "cltermux:+1",
            "cltermux:",
            "other:42",
            "cltermux:1.5",
            "cltermux: 1",
        ] {
            assert!(!valid_uid(uid), "{uid}");
        }
    }

    #[test]
    fn uid_accepts_eighteen_digits_and_rejects_nineteen() {
        assert!(valid_uid(&format!("cltermux:{}", "1".repeat(18))));
        assert!(valid_uid(&format!("cltermux:1{}", "0".repeat(17))));
        assert!(!valid_uid(&format!("cltermux:{}", "1".repeat(19))));
        assert!(!valid_uid(&format!("cltermux:9{}", "0".repeat(18))));
    }
}
