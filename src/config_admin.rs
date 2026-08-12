use std::env;

use super::ConfigError;

const ADMIN_TOKEN_MIN_BYTES: usize = 32;

const COMMON_WEAK_VALUES: &[&str] = &[
    "admin",
    "admin-token",
    "admin_token",
    "administrator",
    "change-me",
    "changeme",
    "default",
    "default-token",
    "dev",
    "dev-token",
    "development",
    "development-token",
    "example",
    "example-token",
    "password",
    "password123",
    "secret",
    "secret-token",
    "test",
    "test-token",
];

const PUBLIC_PLACEHOLDER_MARKERS: &[&str] = &[
    "change-this-admin-token",
    "example-admin-token",
    "insert-token-here",
    "put-your-token-here",
    "replace-me",
    "replace-this-token",
    "your-admin-token",
    "your-token",
];

pub(super) fn admin_token_from_env() -> Result<String, ConfigError> {
    let token = env::var("ADMIN_TOKEN").unwrap_or_default();
    validate_admin_token(&token)?;
    Ok(token)
}

fn validate_admin_token(token: &str) -> Result<(), ConfigError> {
    // An empty value is a supported deployment: it disables only the system Bearer
    // token channel (issue #305). Browser sessions with a sufficient role and valid
    // CSRF binding keep working, and the first-owner bootstrap endpoint stays public
    // while no owner exists, so an unset token must not fail startup.
    if token.is_empty() {
        return Ok(());
    }

    let normalized = token.to_ascii_lowercase();
    let is_common_weak_value = COMMON_WEAK_VALUES.contains(&normalized.as_str());
    let is_public_placeholder = PUBLIC_PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker));

    if token.len() < ADMIN_TOKEN_MIN_BYTES
        || token.chars().any(char::is_whitespace)
        || is_common_weak_value
        || is_public_placeholder
    {
        return Err(ConfigError::InvalidValue("ADMIN_TOKEN"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_DEVELOPMENT_TOKEN: &str = "local-development-admin-token-012345";

    #[test]
    fn empty_admin_token_remains_allowed() {
        assert_eq!(validate_admin_token(""), Ok(()));
    }

    #[test]
    fn explicit_long_development_token_is_allowed() {
        assert_eq!(validate_admin_token(VALID_DEVELOPMENT_TOKEN), Ok(()));
    }

    #[test]
    fn short_admin_tokens_are_rejected() {
        assert_eq!(
            validate_admin_token("short-admin-token"),
            Err(ConfigError::InvalidValue("ADMIN_TOKEN"))
        );
    }

    #[test]
    fn public_placeholders_are_rejected_case_insensitively() {
        for token in [
            "change-this-admin-token",
            "CHANGE-THIS-ADMIN-TOKEN",
            "change-this-admin-token-with-extra-length-0123456789",
            "password",
            "ADMIN-TOKEN",
        ] {
            assert_eq!(
                validate_admin_token(token),
                Err(ConfigError::InvalidValue("ADMIN_TOKEN")),
                "placeholder token must be rejected"
            );
        }
    }

    #[test]
    fn whitespace_cannot_bypass_placeholder_rejection() {
        for token in [
            " change-this-admin-token ",
            "\tCHANGE-THIS-ADMIN-TOKEN\n",
            "local development admin token with spaces 0123456789",
        ] {
            assert_eq!(
                validate_admin_token(token),
                Err(ConfigError::InvalidValue("ADMIN_TOKEN")),
                "whitespace-containing token must be rejected"
            );
        }
    }

    #[test]
    fn configuration_error_does_not_contain_the_token() {
        let token = "CHANGE-THIS-ADMIN-TOKEN-WITH-SENSITIVE-SUFFIX";
        let error = validate_admin_token(token).expect_err("placeholder must be rejected");
        let rendered = error.to_string();

        assert_eq!(rendered, "invalid configuration value: ADMIN_TOKEN");
        assert!(!rendered.contains(token));
    }
}
