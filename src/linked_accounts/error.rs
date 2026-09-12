//! Error taxonomy for linked-account use cases.

use crate::integrations::cltermux::types::IntegrationError;

#[derive(Debug, thiserror::Error)]
pub enum LinkedAccountServiceError {
    #[error("linked account was not found")]
    NotFound,
    #[error("linked account is already occupied")]
    AlreadyLinked,
    #[error("the browser session changed while binding the account")]
    SessionInvalid,
    #[error("the user account is disabled")]
    UserDisabled,
    #[error("provider is not configured")]
    NotConfigured,
    #[error("refresh is rate limited")]
    RateLimited { retry_after_secs: u32 },
    #[error("provider operation failed")]
    Integration(#[from] IntegrationError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("external identity lookup failed: {0}")]
    External(#[from] crate::oauth::providers::service::ExternalOAuthError),
    #[error("stored linked account snapshot is invalid")]
    CorruptSnapshot,
}
