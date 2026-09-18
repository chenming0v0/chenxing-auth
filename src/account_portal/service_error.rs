//! 消费方业务错误。不携带凭据、令牌或提供方原始 message。

use std::time::Duration;

use thiserror::Error;

use super::crypto::CryptoError;
use super::error::{ClientError, KnownErrorCode, ProtocolError};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("account portal storage is unavailable")]
    Unavailable,
    #[error("account portal session is no longer valid")]
    SessionInvalid,
    #[error("account portal user is disabled")]
    UserDisabled,
    #[error("account portal provider was not found")]
    ProviderNotFound,
    #[error("account portal provider is disabled")]
    ProviderDisabled,
    #[error("account portal provider identity cannot be changed while grants exist")]
    IdentityLocked,
    #[error("account portal configuration conflicted")]
    Conflict,
    #[error("account portal request is invalid")]
    InvalidInput(&'static str),
    #[error("account portal credentials were rejected")]
    CredentialInvalid,
    #[error("account portal binding was not found")]
    BindingNotFound,
    #[error("account portal binding is no longer active")]
    BindingTombstoned,
    #[error("account portal grant requires explicit reauthorization")]
    ReauthorizationRequired,
    #[error("account portal provider rate limited the request")]
    RateLimited { retry_after: Option<Duration> },
    #[error("account portal provider is unavailable")]
    ProviderUnavailable { retry_after: Option<Duration> },
    #[error("account portal protocol response is invalid")]
    Protocol(ProtocolError),
    #[error("account portal cryptography failed")]
    Crypto,
    #[error("account portal audit is unavailable")]
    AuditUnavailable,
}

impl From<super::store::StoreError> for ServiceError {
    fn from(error: super::store::StoreError) -> Self {
        match error {
            super::store::StoreError::IssuerTaken
            | super::store::StoreError::UserSlotTaken
            | super::store::StoreError::UidTaken
            | super::store::StoreError::Conflict => Self::Conflict,
            super::store::StoreError::Database(error) => Self::from(error),
        }
    }
}

impl From<crate::sqlx::Error> for ServiceError {
    fn from(error: crate::sqlx::Error) -> Self {
        tracing::error!(error = %error, "account portal database operation failed");
        Self::Unavailable
    }
}

impl From<CryptoError> for ServiceError {
    fn from(error: CryptoError) -> Self {
        tracing::error!(error = %error, "account portal crypto operation failed");
        Self::Crypto
    }
}

impl From<crate::users::UserSessionValidation> for ServiceError {
    fn from(value: crate::users::UserSessionValidation) -> Self {
        match value {
            crate::users::UserSessionValidation::Valid => Self::Unavailable,
            crate::users::UserSessionValidation::SessionInvalid => Self::SessionInvalid,
            crate::users::UserSessionValidation::UserDisabled => Self::UserDisabled,
        }
    }
}

impl From<crate::oauth::providers::secrets::SecretError> for ServiceError {
    fn from(error: crate::oauth::providers::secrets::SecretError) -> Self {
        tracing::error!(error = %error, "account portal secret operation failed");
        Self::Crypto
    }
}

impl From<ClientError> for ServiceError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Transport(_) => Self::ProviderUnavailable { retry_after: None },
            ClientError::ResponseTooLarge | ClientError::UnexpectedStatus(_) => {
                Self::ProviderUnavailable { retry_after: None }
            }
            ClientError::InvalidResponse(protocol) => Self::Protocol(protocol),
            ClientError::Provider(failure) => match failure.code {
                KnownErrorCode::CredentialInvalid => Self::CredentialInvalid,
                KnownErrorCode::InvalidRefreshToken
                | KnownErrorCode::InvalidAccessToken
                | KnownErrorCode::IssuanceAlreadyCommitted
                | KnownErrorCode::RefreshAlreadyCommitted => Self::ReauthorizationRequired,
                KnownErrorCode::AccountDisabled => Self::BindingTombstoned,
                KnownErrorCode::AccountNotFound => Self::BindingNotFound,
                KnownErrorCode::BindingConflict => Self::Conflict,
                KnownErrorCode::RateLimited => Self::RateLimited {
                    retry_after: failure.retry_after,
                },
                KnownErrorCode::ProviderUnavailable => Self::ProviderUnavailable {
                    retry_after: failure.retry_after,
                },
                KnownErrorCode::InvalidClient | KnownErrorCode::InvalidRequest => {
                    Self::ProviderUnavailable { retry_after: None }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_portal::error::ProviderFailure;

    #[test]
    fn committed_issuance_cannot_be_treated_as_a_retryable_transport_error() {
        let error = ClientError::Provider(ProviderFailure {
            code: KnownErrorCode::IssuanceAlreadyCommitted,
            retry_after: None,
        });
        assert!(matches!(
            ServiceError::from(error),
            ServiceError::ReauthorizationRequired
        ));
    }

    #[test]
    fn status_code_mismatch_does_not_destroy_a_grant() {
        let error = ClientError::UnexpectedStatus(502);
        assert!(matches!(
            ServiceError::from(error),
            ServiceError::ProviderUnavailable { .. }
        ));
    }
}
