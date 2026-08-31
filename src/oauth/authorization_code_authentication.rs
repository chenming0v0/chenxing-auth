use super::AuthorizationCodeIssueError;
use crate::{
    oauth::authorization::{ValidatedAuthorizationRequest, reauthentication_is_satisfied},
    sessions::domain::decode_session_token_hash,
    state::AppState,
};

pub(super) async fn enforce_authentication_constraints(
    state: &AppState,
    user_id: &str,
    validated: &ValidatedAuthorizationRequest,
) -> Result<(), AuthorizationCodeIssueError> {
    let reauth_required = validated.reauth_required
        || validated
            .prompt
            .as_deref()
            .is_some_and(|prompt| prompt.split_whitespace().any(|value| value == "login"));
    if !reauth_required && validated.max_age.is_none() {
        return Ok(());
    }
    let encoded_session_hash = validated
        .session_token_hash
        .as_deref()
        .ok_or(AuthorizationCodeIssueError::InvalidSession)?;
    let session_hash = decode_session_token_hash(encoded_session_hash)
        .ok_or(AuthorizationCodeIssueError::InvalidSession)?;
    let session = match state.sessions.find_by_token_hash(&session_hash).await {
        Ok(Some(session))
            if session.user_id == user_id && session.is_active_at(state.clock.now()) =>
        {
            session
        }
        Ok(_) => return Err(AuthorizationCodeIssueError::InvalidSession),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to revalidate OAuth issuing session");
            return Err(AuthorizationCodeIssueError::TemporarilyUnavailable);
        }
    };
    if !reauthentication_is_satisfied(
        encoded_session_hash,
        validated.reauth_session_token_hash.as_deref(),
        session.created_at,
        state.clock.now(),
        validated.max_age,
        reauth_required,
    ) {
        return Err(AuthorizationCodeIssueError::LoginRequired);
    }
    Ok(())
}
