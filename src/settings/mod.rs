pub mod domain;
pub mod repository;
pub mod security_limits;
pub mod service;

pub use domain::{
    EmailPolicySetting, PasskeyAuthenticatorAttachment, PasskeySetting, PasskeyUserVerification,
    SmtpSetting, SmtpSettingUpdate,
};
pub use security_limits::SecurityLimitsSetting;
pub use service::{SettingsService, SettingsServiceError};

pub const REGISTRATION_EMAIL_FROM_KEY: &str = "registration_email_from";
pub const PASSKEY_KEY: &str = "passkey";
pub const EMAIL_POLICY_KEY: &str = "email_policy";
pub const SMTP_KEY: &str = "smtp";
pub const SECURITY_LIMITS_KEY: &str = "security_limits";
