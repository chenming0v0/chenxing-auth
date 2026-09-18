use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::error;
use crate::oauth::response::with_no_store_headers;

use super::service_error::ServiceError;

pub fn service_error(error: ServiceError) -> Response {
    let retry_after = match &error {
        ServiceError::RateLimited { retry_after }
        | ServiceError::ProviderUnavailable { retry_after } => *retry_after,
        _ => None,
    };
    let mut response = match error {
        ServiceError::InvalidInput(field) => {
            error::bad_request("invalid_request", format!("invalid field `{field}`"))
        }
        ServiceError::SessionInvalid => {
            error::unauthorized("session_invalid", "session is no longer valid")
        }
        ServiceError::UserDisabled => error::forbidden("user_disabled", "user is disabled"),
        ServiceError::ProviderNotFound | ServiceError::BindingNotFound => {
            error::not_found("not_found", "resource was not found")
        }
        ServiceError::ProviderDisabled => {
            error::forbidden("provider_disabled", "provider is disabled")
        }
        ServiceError::IdentityLocked => error::conflict(
            "identity_locked",
            "provider identity cannot be changed while grants exist",
        ),
        ServiceError::Conflict => error::conflict("conflict", "the request conflicted"),
        ServiceError::CredentialInvalid => {
            error::unprocessable_entity("credential_invalid", "credentials were rejected")
        }
        ServiceError::BindingTombstoned => {
            error::forbidden("binding_revoked", "the binding is no longer active")
        }
        ServiceError::ReauthorizationRequired => error::conflict(
            "reauthorization_required",
            "the grant cannot be recovered and must be reauthorized",
        ),
        ServiceError::RateLimited { .. } => {
            error::too_many_requests("rate_limited", "provider rate limited the request")
        }
        ServiceError::ProviderUnavailable { .. }
        | ServiceError::Unavailable
        | ServiceError::Crypto
        | ServiceError::AuditUnavailable => {
            error::service_unavailable("provider_unavailable", "the provider is unavailable")
        }
        ServiceError::Protocol(_) => {
            error::bad_request("invalid_response", "provider response was invalid")
        }
    };
    if let Some(seconds) = retry_after {
        if let Ok(value) = axum::http::HeaderValue::from_str(&seconds.as_secs().to_string()) {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
    }
    with_no_store_headers(response)
}

pub fn json_ok<T: serde::Serialize>(value: T) -> Response {
    with_no_store_headers(axum::Json(value).into_response())
}

pub fn json_created<T: serde::Serialize>(value: T) -> Response {
    with_no_store_headers((StatusCode::CREATED, axum::Json(value)).into_response())
}

pub fn no_content() -> Response {
    with_no_store_headers(StatusCode::NO_CONTENT.into_response())
}
