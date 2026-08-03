use axum::{
    extract::{Form, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use super::{
    client_auth::{ClientCredentialError, resolve_client_credentials},
    token::decode_access_token,
};
use crate::{error, state::AppState};

#[derive(Debug, Deserialize)]
pub struct RevocationRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<RevocationRequest>,
) -> Response {
    let credentials = match resolve_client_credentials(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    ) {
        Ok(credentials) => credentials,
        Err(ClientCredentialError::MultipleMethods | ClientCredentialError::Invalid) => {
            return error::oauth_invalid_client();
        }
        Err(ClientCredentialError::Missing) => {
            return error::oauth_invalid_client();
        }
    };
    match state
        .clients
        .verify_credentials(&credentials.client_id, &credentials.client_secret)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return error::oauth_invalid_client();
        }
        Err(client_error) => {
            tracing::error!(error = %client_error, "failed to verify revocation client credentials");
            return error::oauth_temporarily_unavailable();
        }
    }
    if request.token.is_empty() {
        return error::oauth_bad_request("invalid_request", "token is required");
    }

    if !matches!(
        request.token_type_hint.as_deref(),
        None | Some("access_token") | Some("refresh_token")
    ) {
        return error::oauth_bad_request(
            "unsupported_token_type",
            "token type hint is unsupported",
        );
    }

    let hint = request.token_type_hint.as_deref();
    if matches!(hint, Some("refresh_token") | None) {
        match state.refresh_tokens.find(&request.token).await {
            Ok(Some(refresh)) if refresh.client_id == credentials.client_id => {
                if let Err(store_error) = state.refresh_tokens.remove(&request.token).await {
                    tracing::error!(error = %store_error, "failed to revoke refresh token");
                    return error::oauth_temporarily_unavailable();
                }
                return ().into_response();
            }
            Ok(_) => {}
            Err(store_error) => {
                tracing::error!(error = %store_error, "failed to look up refresh token");
                return error::oauth_temporarily_unavailable();
            }
        }
    }

    if matches!(hint, Some("access_token") | None)
        && let Ok(claims) = decode_access_token(
            &state.keys,
            &state.config.issuer_url,
            &credentials.client_id,
            &request.token,
        )
    {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if let Ok(expires_at) = i64::try_from(claims.exp) {
            let ttl = expires_at.saturating_sub(now);
            if ttl > 0
                && let Err(store_error) = state.revocations.revoke(&request.token, ttl as u64).await
            {
                tracing::error!(error = %store_error, "failed to revoke access token");
                return error::oauth_temporarily_unavailable();
            }
        }
    }

    ().into_response()
}
