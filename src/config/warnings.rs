use super::{Config, ConfigError};

/// Security-posture warning discovered while building [`Config`].
///
/// Construction must not call `tracing` itself: `main` loads config before a
/// subscriber exists, so those events would be dropped. Collect the warnings
/// as data and emit them after `install_tracing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigWarning {
    HttpIssuerSecureCookie,
    /// Issue #348: empty token disables the initialized admin surface.
    EmptyAdminToken,
    /// Issue #343: loopback/plaintext provider exception is a development switch.
    OauthProviderLoopbackEnabled,
    /// #111: missing TRUSTED_PROXIES collapses rate limits onto the proxy IP.
    NoTrustedProxies,
}

impl ConfigWarning {
    pub const fn message(self) -> &'static str {
        match self {
            Self::HttpIssuerSecureCookie => {
                "COOKIE_SECURE=true with an HTTP APP_ISSUER: browsers may reject the Secure cookies"
            }
            Self::EmptyAdminToken => {
                "ADMIN_TOKEN not set: the admin API surface is disabled. Both the \
                 system Bearer channel and the browser-session channel are rejected; \
                 only the first-owner bootstrap endpoint stays public while no owner \
                 exists."
            }
            Self::OauthProviderLoopbackEnabled => {
                "OAUTH_PROVIDER_LOOPBACK_ENABLED=true: provider endpoints may target \
                 loopback hosts over plaintext http. This is a development-only \
                 exception; decrypted client secrets and user access tokens are sent \
                 to these endpoints. Keep disabled in production."
            }
            Self::NoTrustedProxies => {
                "TRUSTED_PROXIES not set: X-Forwarded-For is ignored and all client \
                 IPs resolve to the direct peer. Set TRUSTED_PROXIES if behind a proxy."
            }
        }
    }

    pub const fn kind(self) -> &'static str {
        match self {
            Self::HttpIssuerSecureCookie => "http_issuer_secure_cookie",
            Self::EmptyAdminToken => "empty_admin_token",
            Self::OauthProviderLoopbackEnabled => "oauth_provider_loopback_enabled",
            Self::NoTrustedProxies => "no_trusted_proxies",
        }
    }

    pub fn emit(self) {
        match self {
            Self::HttpIssuerSecureCookie => {
                tracing::warn!(
                    config_warning = self.kind(),
                    issuer_scheme = "http",
                    "{}",
                    self.message()
                );
            }
            Self::EmptyAdminToken
            | Self::OauthProviderLoopbackEnabled
            | Self::NoTrustedProxies => {
                tracing::warn!(config_warning = self.kind(), "{}", self.message());
            }
        }
    }
}

impl Config {
    pub fn startup_warnings(&self) -> Vec<ConfigWarning> {
        let mut warnings = Vec::new();
        if self.cookie_secure && has_http_issuer(self) {
            warnings.push(ConfigWarning::HttpIssuerSecureCookie);
        }
        if self.admin_token.is_empty() {
            warnings.push(ConfigWarning::EmptyAdminToken);
        }
        if self.oauth_provider_loopback_enabled {
            warnings.push(ConfigWarning::OauthProviderLoopbackEnabled);
        }
        if self.trusted_proxies.is_empty() {
            warnings.push(ConfigWarning::NoTrustedProxies);
        }
        warnings
    }

    pub fn emit_startup_warnings(&self) {
        for warning in self.startup_warnings() {
            warning.emit();
        }
    }
}

fn has_http_issuer(config: &Config) -> bool {
    // `from_env` leaves APP_ISSUER on `legacy_issuer_import` until the database
    // is consulted, so the binary path has no runtime `issuer` yet.
    config
        .issuer
        .as_ref()
        .is_some_and(|issuer| !issuer.is_https())
        || config
            .legacy_issuer_import
            .as_deref()
            .is_some_and(is_http_url)
}

fn is_http_url(value: &str) -> bool {
    url::Url::parse(value.trim()).is_ok_and(|url| url.scheme() == "http")
}

/// Fail closed on a bad `RUST_LOG` expression without formatting `Config`.
pub(crate) fn parse_log_filter(filter: &str) -> Result<tracing_subscriber::EnvFilter, ConfigError> {
    tracing_subscriber::EnvFilter::try_new(filter)
        .map_err(|_| ConfigError::InvalidValue("RUST_LOG"))
}

pub fn install_tracing(filter: &str) -> Result<(), ConfigError> {
    tracing_subscriber::fmt()
        .with_env_filter(parse_log_filter(filter)?)
        .with_target(false)
        .init();
    Ok(())
}

#[cfg(test)]
#[path = "warnings_tests.rs"]
mod tests;
