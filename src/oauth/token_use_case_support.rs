use super::super::{
    code::AuthorizationCode,
    id_token::{IdTokenProfile, issue_id_token_with_profile},
    pkce::verify_s256,
    session::active_user_id,
    token::issue_access_token,
};
use super::{OAuthError, TokenResponse};
use crate::{sessions::domain::decode_session_token_hash, state::AppState, users::domain::UserId};

pub(super) fn validate_code_binding(
    client_id: &str,
    redirect_uri: &str,
    code_verifier: &str,
    code: &AuthorizationCode,
) -> Result<(), OAuthError> {
    if code.client_id != client_id || code.redirect_uri != redirect_uri {
        return Err(OAuthError::invalid_grant());
    }
    if verify_code_is_redeemable(code).is_err() {
        return Err(OAuthError::invalid_grant());
    }
    if verify_s256(code_verifier, &code.code_challenge).is_err() {
        tracing::info!("OAuth PKCE verification failed");
        return Err(OAuthError::invalid_grant());
    }
    Ok(())
}

/// Issue token data without constructing an HTTP response. This preserves the existing
/// response helper's order: active user, access token, optional OIDC profile and ID token.
pub(crate) async fn issue_token_response(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    scopes: &[String],
    refresh_token: Option<String>,
    nonce: Option<&str>,
    auth_time: Option<i64>,
) -> Result<TokenResponse, OAuthError> {
    match active_user_id(state, user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(OAuthError::invalid_authorization_grant()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load token user");
            return Err(OAuthError::temporarily_unavailable());
        }
    }
    let access_token = match issue_access_token(
        &state.keys,
        &state.config.issuer_url,
        user_id,
        client_id,
        scopes,
        state.config.access_token_ttl_seconds,
    ) {
        Ok(token) => token,
        Err(token_error) => {
            tracing::error!(error = %token_error, "failed to issue OAuth access token");
            return Err(OAuthError::temporarily_unavailable());
        }
    };
    let id_token = issue_id_token(state, user_id, client_id, scopes, nonce, auth_time).await?;
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.access_token_ttl_seconds,
        scope: scopes.join(" "),
        refresh_token,
        id_token,
    })
}

async fn issue_id_token(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    scopes: &[String],
    nonce: Option<&str>,
    auth_time: Option<i64>,
) -> Result<Option<String>, OAuthError> {
    if !scopes.iter().any(|scope| scope == "openid") {
        return Ok(None);
    }
    let Ok(subject) = user_id.parse::<UserId>() else {
        tracing::error!(user_id, "cannot issue ID token for invalid user id");
        return Err(OAuthError::temporarily_unavailable());
    };
    let profile = match state.users.find_profile(subject).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return Err(OAuthError::temporarily_unavailable()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load ID token profile");
            return Err(OAuthError::temporarily_unavailable());
        }
    };
    issue_id_token_with_profile(
        &state.keys,
        &state.config.issuer_url,
        user_id,
        client_id,
        IdTokenProfile {
            nonce,
            email: scopes
                .iter()
                .any(|scope| scope == "email")
                .then_some(profile.email.as_str()),
            name: scopes
                .iter()
                .any(|scope| scope == "profile")
                .then_some(profile.display_name.as_deref())
                .flatten(),
            auth_time,
        },
        state.config.id_token_ttl_seconds,
    )
    .map(Some)
    .map_err(|token_error| {
        tracing::error!(error = %token_error, "failed to issue OIDC ID token");
        OAuthError::temporarily_unavailable()
    })
}

/// 校验授权码绑定的会话仍然有效，并返回该会话的认证时刻。
///
/// 返回的时间戳是会话建立时间，用作 ID Token 的 `auth_time`，而不是令牌签发时刻。
/// `session_token_hash` 为 `None` 时走无浏览器会话的兼容路径，不声明 `auth_time`。
pub(super) async fn authorization_code_session_auth_time(
    state: &AppState,
    code: &AuthorizationCode,
) -> Result<Option<i64>, OAuthError> {
    let Some(session_hash) = code.session_token_hash.as_deref() else {
        return Ok(None);
    };
    let Some(session_hash) = decode_session_token_hash(session_hash) else {
        tracing::info!(
            client_id = %code.client_id,
            "OAuth authorization code rejected: session binding is invalid"
        );
        return Err(OAuthError::invalid_grant());
    };
    match state.sessions.find_by_token_hash(&session_hash).await {
        Ok(Some(session)) if session.is_active() => Ok(Some(session.created_at.unix_timestamp())),
        Ok(_) => {
            tracing::info!(
                client_id = %code.client_id,
                "OAuth authorization code rejected: issuing session is no longer active"
            );
            Err(OAuthError::invalid_grant())
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to load authorization code session");
            Err(OAuthError::temporarily_unavailable())
        }
    }
}

pub(super) async fn compensate_authorization_code_exchange(
    state: &AppState,
    code: &AuthorizationCode,
    refresh_value: &str,
) {
    if let Err(store_error) = state.refresh_tokens.remove(refresh_value).await {
        tracing::warn!(error = %store_error, "failed to remove refresh token during OAuth compensation");
    }
    let ttl_seconds = authorization_code_restore_ttl(code);
    if let Err(store_error) = state.authorization_codes.restore(code, ttl_seconds).await {
        tracing::warn!(error = %store_error, "failed to restore OAuth authorization code");
    }
}

fn authorization_code_restore_ttl(code: &AuthorizationCode) -> u64 {
    let remaining_seconds = (code.expires_at - time::OffsetDateTime::now_utc()).whole_seconds();
    if remaining_seconds <= 0 {
        return 1;
    }
    u64::try_from(remaining_seconds).unwrap_or(1)
}

fn verify_code_is_redeemable(code: &AuthorizationCode) -> Result<(), ()> {
    let mut code = code.clone();
    code.redeem_at(time::OffsetDateTime::now_utc())
        .map_err(|_| ())
}
