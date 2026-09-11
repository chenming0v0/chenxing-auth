use axum::{
    http::{
        HeaderValue,
        header::{CACHE_CONTROL, RETRY_AFTER},
    },
    response::Response,
};

use crate::{error, integrations::cltermux::types::IntegrationError};

use super::LinkedAccountServiceError;

pub(crate) fn service_code(error_value: &LinkedAccountServiceError) -> &'static str {
    match error_value {
        LinkedAccountServiceError::Integration(error) => error.code(),
        LinkedAccountServiceError::AlreadyLinked => "account_already_linked",
        LinkedAccountServiceError::RateLimited { .. } => "rate_limited",
        LinkedAccountServiceError::NotFound => "linked_account_not_found",
        LinkedAccountServiceError::NotConfigured => "provider_capability_unsupported",
        LinkedAccountServiceError::SessionInvalid => "invalid_session",
        LinkedAccountServiceError::UserDisabled => "user_disabled",
        LinkedAccountServiceError::External(_)
        | LinkedAccountServiceError::Database(_)
        | LinkedAccountServiceError::CorruptSnapshot => "internal_error",
    }
}

pub(crate) fn map_service_error(error_value: LinkedAccountServiceError) -> Response {
    let code = service_code(&error_value);
    let mut response = match error_value {
        LinkedAccountServiceError::Integration(IntegrationError::ProviderTimeout) => {
            error::gateway_timeout(code, "the provider request timed out")
        }
        LinkedAccountServiceError::Integration(IntegrationError::ProviderUnavailable) => {
            error::service_unavailable(code, "the provider is temporarily unavailable")
        }
        LinkedAccountServiceError::Integration(IntegrationError::RateLimited { .. })
        | LinkedAccountServiceError::RateLimited { .. } => {
            error::too_many_requests(code, "the provider request is rate limited")
        }
        LinkedAccountServiceError::Integration(IntegrationError::AccountDisabled) => {
            error::forbidden(code, "the linked account is disabled")
        }
        LinkedAccountServiceError::Integration(IntegrationError::AccountNotFound) => {
            error::not_found(code, "the linked account was not found")
        }
        LinkedAccountServiceError::Integration(IntegrationError::InvalidCredential) => {
            error::unprocessable_entity(code, "the credentials are invalid")
        }
        LinkedAccountServiceError::AlreadyLinked => {
            error::conflict(code, "the account is already linked")
        }
        LinkedAccountServiceError::NotFound => {
            error::not_found(code, "the linked account was not found")
        }
        LinkedAccountServiceError::SessionInvalid => {
            error::unauthorized(code, "the session is invalid")
        }
        LinkedAccountServiceError::UserDisabled => {
            error::unauthorized(code, "the user account is disabled")
        }
        LinkedAccountServiceError::NotConfigured => {
            error::conflict(code, "the provider capability is unavailable")
        }
        LinkedAccountServiceError::Integration(_) => {
            error::bad_gateway(code, "the provider request failed")
        }
        LinkedAccountServiceError::External(_)
        | LinkedAccountServiceError::Database(_)
        | LinkedAccountServiceError::CorruptSnapshot => error::internal(),
    };
    if let LinkedAccountServiceError::RateLimited { retry_after_secs }
    | LinkedAccountServiceError::Integration(IntegrationError::RateLimited {
        retry_after_secs,
    }) = error_value
        && let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string())
    {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
