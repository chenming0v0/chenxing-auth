use super::{
    issue_token_response, OAuthError, RefreshExchangeError, TokenRequest, TokenResponse,
};
use crate::{state::AppState, users::domain::UserId};

use super::super::{
    refresh_store::Tombstone,
    session::active_user_id,
    token_security::record_token_event,
};

/// Exchange a refresh token after the token endpoint has authenticated the client.
pub(super) async fn exchange_refresh_token(
    state: &AppState,
    request: TokenRequest,
) -> Result<TokenResponse, RefreshExchangeError> {
    let Some(refresh_value) = request.refresh_token.as_deref() else {
        return Err(OAuthError::bad_request("invalid_request", "refresh_token is required").into());
    };
    let Some(client_id) = request.client_id.as_deref() else {
        return Err(OAuthError::InvalidClient.into());
    };
    let refresh = match state.refresh_tokens.find(refresh_value).await {
        Ok(Some(refresh)) => refresh,
        Ok(None) => {
            // A missing token may be either unknown or a replay of a normally rotated token.
            return handle_missing_refresh_token(state, client_id, refresh_value).await;
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve refresh token");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    };

    if refresh
        .validate(client_id, time::OffsetDateTime::now_utc())
        .is_err()
    {
        return record_and_return_invalid(
            state,
            Some(&refresh.user_id),
            client_id,
            "invalid_token",
        )
        .await;
    }
    match state
        .revocations
        .is_consent_revoked(&refresh.user_id, client_id)
        .await
    {
        Ok(true) => return Err(OAuthError::invalid_refresh_grant().into()),
        Ok(false) => {}
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to check OAuth consent revocation");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    }

    let Ok(user_id) = refresh.user_id.parse::<UserId>() else {
        return Err(OAuthError::invalid_refresh_grant().into());
    };
    match state
        .consents
        .has_scopes(user_id, client_id, &refresh.scopes)
        .await
    {
        Ok(true) => {}
        Ok(false) => return Err(OAuthError::invalid_refresh_grant().into()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to check refresh token consent");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    }
    match active_user_id(state, &refresh.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(OAuthError::invalid_refresh_grant().into()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load refresh token user");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    }

    let scopes = select_scopes(request.scope.as_deref(), &refresh.scopes)?;
    // rotate() inherits issued_at and family_id so absolute lifetime and replay revocation
    // semantics survive rotation.
    let next_refresh = refresh.rotate(scopes.clone());
    let token = issue_token_response(
        state,
        &refresh.user_id,
        client_id,
        &scopes,
        Some(next_refresh.value.clone()),
        None,
        None,
    )
    .await?;

    // All checks and token issuance happen before this CAS. It is the single credential
    // consumption boundary, and remains atomic with tombstone creation in the store.
    match state
        .refresh_tokens
        .rotate_if_matches(refresh_value, &refresh, &next_refresh)
        .await
    {
        Ok(true) => {
            if record_token_event(
                state,
                Some(&refresh.user_id),
                "token_refresh",
                Some(client_id),
                "success",
            )
            .await
            .is_err()
            {
                if let Err(error_value) = state.refresh_tokens.remove(&next_refresh.value).await {
                    tracing::warn!(
                        error = %error_value,
                        "failed to compensate refresh token after audit persistence failure"
                    );
                }
                if let Err(error_value) = state.refresh_tokens.save(&refresh).await {
                    tracing::warn!(
                        error = %error_value,
                        "failed to restore previous refresh token after audit persistence failure"
                    );
                }
                return Err(RefreshExchangeError::ServerError);
            }
            Ok(token)
        }
        Ok(false) => {
            // A lost CAS race means another request consumed this token concurrently. The
            // matching tombstone identifies the family that must be revoked.
            let tombstone = match state.refresh_tokens.read_tombstone(refresh_value).await {
                Ok(tombstone) => tombstone,
                Err(store_error) => {
                    tracing::error!(error = %store_error, "failed to read refresh token tombstone");
                    return Err(OAuthError::temporarily_unavailable().into());
                }
            };
            match tombstone {
                Some(tombstone) if tombstone.client_id == client_id => {
                    revoke_family_after_replay(state, client_id, &tombstone).await
                }
                _ => {
                    // A missing tombstone is a narrow race in which the family cannot be
                    // located, so reject only this request.
                    tracing::warn!(
                        client_id = %client_id,
                        "refresh rotation lost CAS race but tombstone is missing; \
                         cannot revoke family"
                    );
                    record_and_return_invalid(
                        state,
                        Some(&refresh.user_id),
                        client_id,
                        "token_race",
                    )
                    .await
                }
            }
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to atomically rotate refresh token");
            Err(OAuthError::temporarily_unavailable().into())
        }
    }
}

fn select_scopes(
    requested_scope: Option<&str>,
    original_scopes: &[String],
) -> Result<Vec<String>, OAuthError> {
    match requested_scope {
        Some(scope) => {
            let requested = scope
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if requested
                .iter()
                .any(|scope| !original_scopes.contains(scope))
            {
                return Err(OAuthError::bad_request(
                    "invalid_scope",
                    "requested scope exceeds original grant",
                ));
            }
            Ok(requested)
        }
        None => Ok(original_scopes.to_owned()),
    }
}

async fn handle_missing_refresh_token(
    state: &AppState,
    client_id: &str,
    refresh_value: &str,
) -> Result<TokenResponse, RefreshExchangeError> {
    match state.refresh_tokens.read_tombstone(refresh_value).await {
        Ok(Some(tombstone)) if tombstone.client_id == client_id => {
            revoke_family_after_replay(state, client_id, &tombstone).await
        }
        Ok(Some(_)) => {
            // Do not record the submitted token value; it is a credential.
            tracing::warn!(
                client_id = %client_id,
                "refresh token replay attempt with mismatched client_id; \
                 refusing without revoking the owning family"
            );
            record_and_return_invalid(state, None, client_id, "invalid_token").await
        }
        // No tombstone means an unknown token or one outside the replay-detection window.
        Ok(None) => record_and_return_invalid(state, None, client_id, "invalid_token").await,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to read refresh token tombstone");
            Err(OAuthError::temporarily_unavailable().into())
        }
    }
}

async fn revoke_family_after_replay(
    state: &AppState,
    client_id: &str,
    tombstone: &Tombstone,
) -> Result<TokenResponse, RefreshExchangeError> {
    match state
        .refresh_tokens
        .revoke_family(&tombstone.family_id, client_id, &tombstone.user_id)
        .await
    {
        Ok(revoked) => {
            tracing::warn!(
                client_id = %client_id,
                family_id = %tombstone.family_id,
                revoked_refresh_tokens = revoked,
                "refresh token replay detected; revoked entire token family"
            );
        }
        Err(store_error) => {
            tracing::error!(
                error = %store_error,
                client_id = %client_id,
                family_id = %tombstone.family_id,
                "failed to revoke refresh token family after replay detection"
            );
        }
    }
    record_and_return_invalid(
        state,
        Some(&tombstone.user_id),
        client_id,
        "refresh_replay_detected",
    )
    .await
}

async fn record_and_return_invalid(
    state: &AppState,
    user_id: Option<&str>,
    client_id: &str,
    reason: &str,
) -> Result<TokenResponse, RefreshExchangeError> {
    if record_token_event(
        state,
        user_id,
        "token_refresh_failure",
        Some(client_id),
        reason,
    )
    .await
    .is_err()
    {
        return Err(RefreshExchangeError::ServerError);
    }
    Err(OAuthError::invalid_refresh_grant().into())
}

#[cfg(test)]
mod tests {
    use super::select_scopes;
    use crate::oauth::{refresh::RefreshToken, token_use_case::OAuthError};
    use time::{Duration, OffsetDateTime};

    fn refresh_token() -> RefreshToken {
        RefreshToken::new_at(
            "cx_client".to_owned(),
            "7".to_owned(),
            vec!["openid".to_owned(), "profile".to_owned()],
            OffsetDateTime::UNIX_EPOCH + Duration::days(1),
        )
    }

    #[test]
    fn omitted_scope_reuses_the_original_grant() {
        let refresh = refresh_token();

        assert_eq!(
            select_scopes(None, &refresh.scopes).expect("original scopes are valid"),
            refresh.scopes
        );
    }

    #[test]
    fn requested_scope_cannot_exceed_the_original_grant() {
        let refresh = refresh_token();

        let error = select_scopes(Some("openid email"), &refresh.scopes)
            .expect_err("scope escalation must be rejected");

        assert_eq!(
            error,
            OAuthError::BadRequest {
                code: "invalid_scope",
                description: "requested scope exceeds original grant",
            }
        );
    }

    #[test]
    fn requested_scope_preserves_endpoint_order() {
        let refresh = refresh_token();

        assert_eq!(
            select_scopes(Some("profile openid"), &refresh.scopes)
                .expect("requested scopes are within the grant"),
            vec!["profile".to_owned(), "openid".to_owned()]
        );
    }
}
