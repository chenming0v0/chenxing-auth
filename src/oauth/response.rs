use axum::{
    Json,
    http::{
        HeaderValue, StatusCode,
        header::{CACHE_CONTROL, PRAGMA},
    },
    response::{IntoResponse, Response},
};
use serde::Serialize;

use super::{
    id_token::{IdTokenProfile, issue_id_token_with_profile},
    session::active_user_id,
    token::issue_access_token,
};
use crate::{error, state::AppState};

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

/// `auth_time` 是终端用户完成认证的时刻（会话建立时间），`None` 表示无会话
/// 上下文，ID Token 将省略该 Claim。见 `id_token::IdTokenClaims::auth_time`。
pub async fn issue_token_response(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    scopes: &[String],
    refresh_token: Option<String>,
    nonce: Option<&str>,
    auth_time: Option<i64>,
) -> Response {
    with_no_store_headers(
        issue_token_response_inner(
            state,
            user_id,
            client_id,
            scopes,
            refresh_token,
            nonce,
            auth_time,
        )
        .await,
    )
}

pub fn with_no_store_headers(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn issue_token_response_inner(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    scopes: &[String],
    refresh_token: Option<String>,
    nonce: Option<&str>,
    auth_time: Option<i64>,
) -> Response {
    match active_user_id(state, user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error::oauth_bad_request("invalid_grant", "authorization grant is invalid");
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load token user");
            return error::oauth_temporarily_unavailable();
        }
    }
    let token = match issue_access_token(
        &state.keys,
        &state.config.issuer_url,
        user_id,
        client_id,
        scopes,
        state.config.session_ttl_seconds,
    ) {
        Ok(token) => token,
        Err(token_error) => {
            tracing::error!(error = %token_error, "failed to issue OAuth access token");
            return error::oauth_temporarily_unavailable();
        }
    };
    let id_token = match issue_id_token(state, user_id, client_id, scopes, nonce, auth_time).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token: token,
            token_type: "Bearer",
            expires_in: state.config.session_ttl_seconds,
            scope: scopes.join(" "),
            refresh_token,
            id_token,
        }),
    )
        .into_response()
}

async fn issue_id_token(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    scopes: &[String],
    nonce: Option<&str>,
    auth_time: Option<i64>,
) -> Result<Option<String>, Response> {
    if !scopes.iter().any(|scope| scope == "openid") {
        return Ok(None);
    }
    let Ok(subject) = user_id.parse::<crate::users::domain::UserId>() else {
        tracing::error!(user_id, "cannot issue ID token for invalid user id");
        return Err(error::oauth_temporarily_unavailable());
    };
    let profile = match state.users.find_profile(subject).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return Err(error::oauth_temporarily_unavailable()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load ID token profile");
            return Err(error::oauth_temporarily_unavailable());
        }
    };
    let id_token = issue_id_token_with_profile(
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
        state.config.session_ttl_seconds,
    )
    .map(Some)
    .map_err(|token_error| {
        tracing::error!(error = %token_error, "failed to issue OIDC ID token");
        error::oauth_temporarily_unavailable()
    })?;
    Ok(id_token)
}
