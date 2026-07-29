use axum::{
    Json,
    http::StatusCode,
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

pub async fn issue_token_response(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    scopes: &[String],
    refresh_token: Option<String>,
    nonce: Option<&str>,
) -> Response {
    match active_user_id(state, user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return error::unauthorized("user_disabled", "user account is disabled"),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load token user");
            return error::internal();
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
            return error::internal();
        }
    };
    let id_token = match issue_id_token(state, user_id, client_id, scopes, nonce).await {
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
) -> Result<Option<String>, Response> {
    if !scopes.iter().any(|scope| scope == "openid") {
        return Ok(None);
    }
    let Ok(subject) = user_id.parse::<crate::users::domain::UserId>() else {
        tracing::error!(user_id, "cannot issue ID token for invalid user id");
        return Err(error::internal());
    };
    let profile = match state.users.find_profile(subject).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return Err(error::internal()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load ID token profile");
            return Err(error::internal());
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
        },
        state.config.session_ttl_seconds,
    )
    .map(Some)
    .map_err(|token_error| {
        tracing::error!(error = %token_error, "failed to issue OIDC ID token");
        error::internal()
    })?;
    Ok(id_token)
}
