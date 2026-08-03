use crate::state::AppState;

pub(super) enum PendingRequestBindingError {
    Expired,
    Invalid,
    Storage,
}

pub(super) async fn bind_pending_request(
    state: &AppState,
    request_id: &str,
    session_token: &str,
) -> Result<(), PendingRequestBindingError> {
    let Some(mut pending) = state
        .authorization_requests
        .find(request_id)
        .await
        .map_err(|error_value| {
            tracing::error!(
                error = %error_value,
                "failed to load pending authorization request for external login"
            );
            PendingRequestBindingError::Storage
        })?
    else {
        return Err(PendingRequestBindingError::Expired);
    };
    if pending.request_id != request_id {
        return Err(PendingRequestBindingError::Invalid);
    }
    match pending.session_id.as_deref() {
        None => {}
        Some(existing) if existing == session_token => return Ok(()),
        Some(_) => return Err(PendingRequestBindingError::Invalid),
    }
    pending.session_id = Some(session_token.to_owned());
    state
        .authorization_requests
        .save(&pending)
        .await
        .map_err(|error_value| {
            tracing::error!(
                error = %error_value,
                "failed to bind pending authorization request after external login"
            );
            PendingRequestBindingError::Storage
        })
}
