//! Final `session_epoch` fence after Refresh Token rotation (Issue #476).
//!
//! Redis rotation is already committed when this module runs. A mismatch must
//! roll the successor back so it never becomes a live credential.

use super::super::{OAuthError, RefreshExchangeError, TokenResponse};
use super::{rollback_rotation, tombstone::record_and_return_invalid};
use crate::{oauth::refresh::RefreshToken, state::AppState, users::domain::UserId};

pub(super) async fn confirm_after_rotation(
    state: &AppState,
    client_id: &str,
    refresh: &RefreshToken,
    next_refresh: &RefreshToken,
) -> Result<(), RefreshExchangeError> {
    let Some(expected_epoch) = refresh.session_epoch else {
        rollback_rotation(state, client_id, next_refresh, refresh).await;
        return discard_token(
            record_and_return_invalid(
                state,
                Some(&refresh.user_id),
                client_id,
                "user_credentials_revoked",
            )
            .await,
        );
    };
    let Ok(user_id) = refresh.user_id.parse::<UserId>() else {
        rollback_rotation(state, client_id, next_refresh, refresh).await;
        return discard_token(
            record_and_return_invalid(
                state,
                Some(&refresh.user_id),
                client_id,
                "user_credentials_revoked",
            )
            .await,
        );
    };
    match state
        .sessions
        .acquire_user_generation_guard(user_id, expected_epoch)
        .await
    {
        Ok(Some(guard)) => {
            if let Err(release_error) = guard.release().await {
                tracing::error!(
                    error = %release_error,
                    client_id = %client_id,
                    "failed to release session_epoch fence after refresh rotation"
                );
                rollback_rotation(state, client_id, next_refresh, refresh).await;
                return Err(OAuthError::temporarily_unavailable().into());
            }
            Ok(())
        }
        Ok(None) => {
            rollback_rotation(state, client_id, next_refresh, refresh).await;
            discard_token(
                record_and_return_invalid(
                    state,
                    Some(&refresh.user_id),
                    client_id,
                    "user_credentials_revoked",
                )
                .await,
            )
        }
        Err(store_error) => {
            tracing::error!(
                error = %store_error,
                client_id = %client_id,
                "failed to acquire session_epoch fence after refresh rotation"
            );
            rollback_rotation(state, client_id, next_refresh, refresh).await;
            Err(OAuthError::temporarily_unavailable().into())
        }
    }
}

fn discard_token(
    result: Result<TokenResponse, RefreshExchangeError>,
) -> Result<(), RefreshExchangeError> {
    result.map(|_| ())
}
