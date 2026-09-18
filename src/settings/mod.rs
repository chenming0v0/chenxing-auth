pub mod domain;
pub mod issuer;
pub(crate) mod issuer_passkey;
#[cfg(test)]
mod issuer_passkey_tests;
pub mod issuer_runtime;
#[cfg(test)]
mod issuer_runtime_tests;
pub(crate) mod persisted;
pub mod repository;
pub mod security_limits;
pub mod security_limits_cache;
pub mod service;
pub mod session_lifetime;
mod smtp;
mod smtp_sender;

pub use domain::{
    EmailPolicySetting, PasskeyAuthenticatorAttachment, PasskeySetting, PasskeyUserVerification,
    RegistrationSetting,
};
pub use issuer::{InitializeIssuerOutcome, IssuerSettingError};
pub use issuer_runtime::{
    ISSUER_SYNC_INTERVAL, IssuerRuntime, IssuerRuntimeState, IssuerSnapshot, SystemPhase,
};
pub use persisted::{SettingDiagnostic, SettingInspection};
pub use security_limits::SecurityLimitsSetting;
pub use security_limits_cache::{
    CachedSecurityLimits, SECURITY_LIMITS_CACHE_TTL, SECURITY_LIMITS_ERROR_BACKOFF,
    SecurityLimitsCache, SecurityLimitsSource,
};
pub use service::{SettingsService, SettingsServiceError};
pub use session_lifetime::{DEFAULT_SESSION_TTL_SECONDS, SessionLifetimeSetting};
pub(crate) use smtp::SmtpDeliveryConfig;
pub use smtp::{SmtpPasswordAction, SmtpSetting, SmtpSettingUpdate};

pub const REGISTRATION_EMAIL_FROM_KEY: &str = "registration_email_from";
pub const REGISTRATION_SETTING_KEY: &str = "registration";
pub const PASSKEY_KEY: &str = "passkey";
pub const EMAIL_POLICY_KEY: &str = "email_policy";
pub const SMTP_KEY: &str = "smtp";
pub const SECURITY_LIMITS_KEY: &str = "security_limits";
pub const SESSION_LIFETIME_KEY: &str = "session_lifetime";
