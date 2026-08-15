//! Final consent and credential-generation fences for authorization-code exchange.

use crate::consents::domain::ConsentState;
use crate::{oauth::refresh::RefreshToken, state::AppState, users::domain::UserId};

use super::super::session::active_user_epoch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FinalFenceError {
    Denied(&'static str),
    Unavailable(&'static str),
}

impl FinalFenceError {
    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::Denied(reason) | Self::Unavailable(reason) => reason,
        }
    }

    pub(super) const fn is_denied(self) -> bool {
        matches!(self, Self::Denied(_))
    }
}

pub(super) async fn verify_authorization_code_fences(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    consent_state_version: i64,
    session_epoch: i64,
    refresh: &RefreshToken,
) -> Result<(), FinalFenceError> {
    let subject = user_id
        .parse::<UserId>()
        .map_err(|_| FinalFenceError::Denied("invalid_subject"))?;
    let consent = state
        .consents
        .consent_state(subject, client_id)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "failed to verify consent fence during authorization-code exchange");
            FinalFenceError::Unavailable("consent_fence_check_failed")
        })?;
    if !consent_fence_holds(consent, consent_state_version) {
        remove_refresh(state, refresh, "consent fence failure").await;
        return Err(FinalFenceError::Denied("consent_changed_during_exchange"));
    }
    match active_user_epoch(state, user_id).await {
        Ok(epoch) if session_epoch_fence_holds(epoch, session_epoch) => Ok(()),
        Ok(_) => {
            remove_refresh(state, refresh, "session epoch fence failure").await;
            Err(FinalFenceError::Denied(
                "session_epoch_changed_during_exchange",
            ))
        }
        Err(error) => {
            remove_refresh(state, refresh, "session epoch lookup failure").await;
            tracing::error!(error = %error, "failed to verify session epoch fence during authorization-code exchange");
            Err(FinalFenceError::Unavailable(
                "session_epoch_fence_check_failed",
            ))
        }
    }
}

pub(super) fn consent_fence_holds(consent: Option<ConsentState>, expected_version: i64) -> bool {
    consent.is_some_and(|state| !state.revoked && state.version == expected_version)
}

pub(super) fn session_epoch_fence_holds(current_epoch: Option<i64>, expected_epoch: i64) -> bool {
    current_epoch == Some(expected_epoch)
}

async fn remove_refresh(state: &AppState, refresh: &RefreshToken, context: &'static str) {
    if let Err(error) = state.refresh_tokens.remove(&refresh.value).await {
        tracing::error!(error = %error, context, "failed to remove refresh token after final fence failure");
    }
}
