use std::env;

use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};
use crate::clients::domain::{
    ClientRegistrationLimits, DEFAULT_MAX_REDIRECT_URI_LENGTH, DEFAULT_MAX_REDIRECT_URIS,
    DEFAULT_MAX_SCOPE_LENGTH, DEFAULT_MAX_SCOPES,
};

use super::ConfigError;

pub(super) fn parse_auth_limiter_failure_policy(
    name: &'static str,
    value: &str,
) -> Result<AuthLimiterFailurePolicy, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "fail-open" | "open" => Ok(AuthLimiterFailurePolicy::FailOpen),
        "fail-closed" | "closed" => Ok(AuthLimiterFailurePolicy::FailClosed),
        _ => Err(ConfigError::InvalidValue(name)),
    }
}

pub(super) fn parse_missing_source_ip_policy(
    name: &'static str,
    value: &str,
) -> Result<MissingSourceIpPolicy, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "skip" => Ok(MissingSourceIpPolicy::Skip),
        "reject" | "fail-closed" => Ok(MissingSourceIpPolicy::Reject),
        _ => Err(ConfigError::InvalidValue(name)),
    }
}

fn parse_usize(name: &'static str, value: &str) -> Result<usize, ConfigError> {
    value
        .parse()
        .map_err(|source| ConfigError::InvalidInteger { name, source })
}

pub(super) fn client_registration_limits_from_env() -> Result<ClientRegistrationLimits, ConfigError>
{
    let limits = [
        (
            "OAUTH_CLIENT_MAX_REDIRECT_URIS",
            env::var("OAUTH_CLIENT_MAX_REDIRECT_URIS")
                .ok()
                .unwrap_or_else(|| DEFAULT_MAX_REDIRECT_URIS.to_string()),
        ),
        (
            "OAUTH_CLIENT_MAX_REDIRECT_URI_LENGTH",
            env::var("OAUTH_CLIENT_MAX_REDIRECT_URI_LENGTH")
                .ok()
                .unwrap_or_else(|| DEFAULT_MAX_REDIRECT_URI_LENGTH.to_string()),
        ),
        (
            "OAUTH_CLIENT_MAX_SCOPES",
            env::var("OAUTH_CLIENT_MAX_SCOPES")
                .ok()
                .unwrap_or_else(|| DEFAULT_MAX_SCOPES.to_string()),
        ),
        (
            "OAUTH_CLIENT_MAX_SCOPE_LENGTH",
            env::var("OAUTH_CLIENT_MAX_SCOPE_LENGTH")
                .ok()
                .unwrap_or_else(|| DEFAULT_MAX_SCOPE_LENGTH.to_string()),
        ),
    ];
    let values = limits
        .into_iter()
        .map(|(name, value)| parse_usize(name, &value))
        .collect::<Result<Vec<_>, _>>()?;
    ClientRegistrationLimits::new(values[0], values[1], values[2], values[3])
        .ok_or(ConfigError::InvalidValue("OAUTH_CLIENT_LIMITS"))
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};

    use super::*;

    #[test]
    fn key_ring_parser_preserves_standard_base64_padding_for_multiple_keys() {
        let current = STANDARD.encode([1_u8; 32]);
        let previous = STANDARD.encode([2_u8; 32]);
        let ring = crate::config::parse_auth_encryption_key_ring_value(
            &format!("kid=current:{current},kid=previous:{previous}"),
            Some("current"),
        )
        .expect("valid key ring");

        assert_eq!(ring.active_kid(), "current");
        assert_eq!(ring.active_key().as_bytes(), &[1_u8; 32]);
        assert_eq!(
            ring.key("previous").expect("previous key").as_bytes(),
            &[2_u8; 32]
        );
    }

    #[test]
    fn key_ring_parser_rejects_malformed_entries_without_exposing_key_material() {
        for value in [
            "current=not-a-key",
            "kid=current=not-a-key",
            "kid=current:not-a-key",
            "kid=current:",
            "kid=current:not-a-key,kid=",
        ] {
            let error = crate::config::parse_auth_encryption_key_ring_value(value, None)
                .expect_err("malformed key ring must be rejected");
            assert_eq!(error, ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
            assert!(!error.to_string().contains("not-a-key"));
        }
    }
}
