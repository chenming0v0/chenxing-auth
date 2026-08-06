use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    code::AuthorizationCode,
    id_token::{IdTokenProfile, issue_id_token_with_profile},
    pkce::verify_s256,
    refresh::RefreshToken,
    session::active_user_id,
    token::issue_access_token,
};
use crate::{state::AppState, users::domain::UserId};

#[path = "refresh_use_case.rs"]
mod refresh_use_case;

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OAuthError {
    #[error("OAuth request is invalid: {code}: {description}")]
    BadRequest {
        code: &'static str,
        description: &'static str,
    },
    #[error("client authentication failed")]
    InvalidClient,
    #[error("OAuth service is temporarily unavailable")]
    TemporarilyUnavailable,
}

impl OAuthError {
    fn bad_request(code: &'static str, description: &'static str) -> Self {
        Self::BadRequest { code, description }
    }

    fn invalid_grant() -> Self {
        Self::bad_request("invalid_grant", "authorization code is invalid")
    }

    fn invalid_authorization_grant() -> Self {
        Self::bad_request("invalid_grant", "authorization grant is invalid")
    }

    fn temporarily_unavailable() -> Self {
        Self::TemporarilyUnavailable
    }

    fn invalid_refresh_grant() -> Self {
        Self::bad_request("invalid_grant", "refresh token is invalid")
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RefreshExchangeError {
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    #[error("OAuth server error")]
    ServerError,
}

/// Exchange an authorization code after the token endpoint has authenticated the client.
///
/// All checks that can reject the code happen before `take_if_matches`. That store operation
/// is the single-use CAS boundary; failures after it compensate both credentials in reverse
/// order of their creation.
pub async fn exchange_code(
    state: &AppState,
    request: TokenRequest,
) -> Result<TokenResponse, OAuthError> {
    let Some(code_value) = request.code.as_deref() else {
        return Err(OAuthError::bad_request("invalid_request", "code is required"));
    };
    let Some(redirect_uri) = request.redirect_uri.as_deref() else {
        return Err(OAuthError::bad_request(
            "invalid_request",
            "redirect_uri is required",
        ));
    };
    let Some(code_verifier) = request.code_verifier.as_deref() else {
        return Err(OAuthError::bad_request(
            "invalid_request",
            "code_verifier is required",
        ));
    };
    let code = match state.authorization_codes.find(code_value).await {
        Ok(Some(code)) => code,
        Ok(None) => return Err(OAuthError::invalid_grant()),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve OAuth authorization code");
            return Err(OAuthError::temporarily_unavailable());
        }
    };
    let Some(client_id) = request.client_id.as_deref() else {
        return Err(OAuthError::InvalidClient);
    };
    validate_code_binding(
        client_id,
        redirect_uri,
        code_verifier,
        &code,
    )?;
    match active_user_id(state, &code.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(OAuthError::invalid_grant()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load authorization code user");
            return Err(OAuthError::temporarily_unavailable());
        }
    }
    // Session binding is intentionally checked before the authorization-code CAS. A failed
    // request must not burn a valid code before binding, expiry, and PKCE all pass.
    let auth_time = authorization_code_session_auth_time(state, &code).await?;
    match state
        .authorization_codes
        .take_if_matches(code_value, &code)
        .await
    {
        Ok(true) => {}
        Ok(false) => return Err(OAuthError::invalid_grant()),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to consume OAuth authorization code");
            return Err(OAuthError::temporarily_unavailable());
        }
    }
    let refresh = RefreshToken::new(
        client_id.to_owned(),
        code.user_id.clone(),
        code.scopes.clone(),
    );
    if let Err(store_error) = state.refresh_tokens.save(&refresh).await {
        tracing::error!(error = %store_error, "failed to store refresh token");
        compensate_authorization_code_exchange(state, &code, &refresh.value).await;
        return Err(OAuthError::temporarily_unavailable());
    }
    let token = match issue_token_response(
        state,
        &code.user_id,
        client_id,
        &code.scopes,
        Some(refresh.value.clone()),
        code.nonce.as_deref(),
        auth_time,
    )
    .await
    {
        Ok(token) => token,
        Err(error) => {
            compensate_authorization_code_exchange(state, &code, &refresh.value).await;
            return Err(error);
        }
    };
    Ok(token)
}

/// Exchange a refresh token after the token endpoint has authenticated the client.
pub async fn exchange_refresh_token(
    state: &AppState,
    request: TokenRequest,
) -> Result<TokenResponse, RefreshExchangeError> {
    refresh_use_case::exchange_refresh_token(state, request).await
}

fn validate_code_binding(
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
/// `session_id` 为 `None` 时走无浏览器会话的兼容路径，不声明 `auth_time`。
async fn authorization_code_session_auth_time(
    state: &AppState,
    code: &AuthorizationCode,
) -> Result<Option<i64>, OAuthError> {
    let Some(session_token) = code.session_id.as_deref() else {
        return Ok(None);
    };
    match state.sessions.find(session_token).await {
        Ok(Some(session)) if session.is_active() => Ok(Some(session.created_at.unix_timestamp())),
        Ok(_) => {
            // 不记录会话令牌，它是凭据。
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

async fn compensate_authorization_code_exchange(
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
    match u64::try_from(remaining_seconds) {
        Ok(seconds) => seconds,
        Err(_) => 1,
    }
}

fn verify_code_is_redeemable(code: &AuthorizationCode) -> Result<(), ()> {
    let mut code = code.clone();
    code.redeem_at(time::OffsetDateTime::now_utc())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    const CLIENT_ID: &str = "cx_client";
    const REDIRECT_URI: &str = "https://client.example/callback";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn authorization_code() -> AuthorizationCode {
        AuthorizationCode::new(
            CLIENT_ID.to_owned(),
            REDIRECT_URI.to_owned(),
            "7".to_owned(),
            vec!["openid".to_owned()],
            CHALLENGE.to_owned(),
        )
    }

    #[test]
    fn binding_and_pkce_validation_accepts_a_valid_code_without_consuming_it() {
        let code = authorization_code();

        assert!(validate_code_binding(CLIENT_ID, REDIRECT_URI, VERIFIER, &code).is_ok());
        assert!(code.redeemed_at.is_none());
    }

    #[test]
    fn redirect_binding_is_rejected_as_invalid_grant() {
        let code = authorization_code();

        let error = validate_code_binding(
            CLIENT_ID,
            "https://attacker.example/callback",
            VERIFIER,
            &code,
        )
        .expect_err("redirect URI mismatch must reject the code");

        assert_eq!(error, OAuthError::invalid_grant());
    }

    #[test]
    fn expired_code_is_rejected_before_pkce_and_remains_unconsumed() {
        let mut code = authorization_code();
        code.expires_at = time::OffsetDateTime::now_utc() - Duration::seconds(1);

        let error = validate_code_binding(
            CLIENT_ID,
            REDIRECT_URI,
            "invalid-verifier-that-would-fail-pkce-too",
            &code,
        )
        .expect_err("expired code must reject");

        assert_eq!(error, OAuthError::invalid_grant());
        assert!(code.redeemed_at.is_none());
    }

    #[test]
    fn pkce_mismatch_is_rejected_without_consuming_the_code() {
        let code = authorization_code();

        let error = validate_code_binding(
            CLIENT_ID,
            REDIRECT_URI,
            "a".repeat(43).as_str(),
            &code,
        )
        .expect_err("PKCE mismatch must reject");

        assert_eq!(error, OAuthError::invalid_grant());
        assert!(code.redeemed_at.is_none());
    }
}
