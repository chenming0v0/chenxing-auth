//! Final publication of an authorization-code exchange (Issue #506).
//!
//! Redis code consumption and candidate Refresh Token persistence happen before this module is
//! entered, but no credential value has been disclosed to the client; Access/ID Tokens exist only
//! in process memory. The final PostgreSQL Session guarded read is the issuance linearization
//! point: a logout that committed first makes it return no row; a logout that loses the row-lock
//! race is ordered after issuance when the short guard is explicitly released.

use super::{
    OAuthError, TokenResponse,
    token_exchange_audit::{exchange_failure, record_token_exchange_success},
    token_use_case_support::{
        AuthorizationCodeSessionBinding, TokenIssueParams, compensate_authorization_code_exchange,
        issue_token_response,
    },
};
use crate::{
    config::IssuerUrl,
    oauth::{code::AuthorizationCode, refresh::RefreshToken},
    state::AppState,
};

pub(super) struct AuthorizationCodeFinalization<'a> {
    pub(super) issuer: &'a IssuerUrl,
    pub(super) code: &'a AuthorizationCode,
    pub(super) client_id: &'a str,
    pub(super) scopes: &'a [String],
    pub(super) refresh: &'a RefreshToken,
    pub(super) session: &'a AuthorizationCodeSessionBinding,
}

pub(super) async fn finalize_authorization_code_exchange(
    state: &AppState,
    finalization: AuthorizationCodeFinalization<'_>,
) -> Result<TokenResponse, OAuthError> {
    let token = match issue_token_response(
        state,
        TokenIssueParams {
            issuer: finalization.issuer,
            user_id: &finalization.code.user_id,
            client_id: finalization.client_id,
            scopes: finalization.scopes,
            refresh_token: Some(finalization.refresh.value.clone()),
            nonce: finalization.code.nonce.as_deref(),
            auth_time: Some(finalization.session.auth_time),
        },
    )
    .await
    {
        Ok(token) => token,
        Err(error) => {
            compensate_authorization_code_exchange(
                state,
                finalization.code,
                &finalization.refresh.value,
            )
            .await;
            return exchange_failure(
                state,
                Some(&finalization.code.user_id),
                Some(finalization.client_id),
                "token_issuance_failed",
                error,
            )
            .await;
        }
    };

    let session_guard = match state
        .sessions
        .acquire_issuance_guard(
            finalization.session.session_id,
            finalization.session.user_id,
            &finalization.session.token_hash,
        )
        .await
    {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            tracing::info!(
                client_id = %finalization.client_id,
                session_id = finalization.session.session_id,
                "OAuth token issuance rejected: issuing Session was revoked concurrently"
            );
            compensate_authorization_code_exchange(
                state,
                finalization.code,
                &finalization.refresh.value,
            )
            .await;
            return exchange_failure(
                state,
                Some(&finalization.code.user_id),
                Some(finalization.client_id),
                "session_revoked_during_exchange",
                OAuthError::invalid_grant(),
            )
            .await;
        }
        Err(store_error) => {
            tracing::error!(
                error = %store_error,
                client_id = %finalization.client_id,
                "failed to acquire Session token-issuance guard"
            );
            compensate_authorization_code_exchange(
                state,
                finalization.code,
                &finalization.refresh.value,
            )
            .await;
            return exchange_failure(
                state,
                Some(&finalization.code.user_id),
                Some(finalization.client_id),
                "session_issuance_guard_failed",
                OAuthError::temporarily_unavailable(),
            )
            .await;
        }
    };

    // The locked read is the linearization point. Release immediately so the guard spans neither
    // Redis nor later pool acquisition.
    if let Err(release_error) = session_guard.release().await {
        tracing::error!(
            error = %release_error,
            client_id = %finalization.client_id,
            session_id = finalization.session.session_id,
            "failed to release Session token-issuance guard"
        );
        compensate_authorization_code_exchange(
            state,
            finalization.code,
            &finalization.refresh.value,
        )
        .await;
        return exchange_failure(
            state,
            Some(&finalization.code.user_id),
            Some(finalization.client_id),
            "session_issuance_guard_release_failed",
            OAuthError::temporarily_unavailable(),
        )
        .await;
    }

    if let Err(audit_error) = record_token_exchange_success(
        state,
        &finalization.code.user_id,
        finalization.client_id,
        finalization.scopes,
    )
    .await
    {
        compensate_authorization_code_exchange(
            state,
            finalization.code,
            &finalization.refresh.value,
        )
        .await;
        tracing::error!(
            error = %audit_error,
            client_id = %finalization.client_id,
            user_id = %finalization.code.user_id,
            "failed to record OAuth token exchange audit event"
        );
        return exchange_failure(
            state,
            Some(&finalization.code.user_id),
            Some(finalization.client_id),
            "success_audit_failed",
            OAuthError::server_error(),
        )
        .await;
    }
    Ok(token)
}
