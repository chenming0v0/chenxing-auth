use axum::{
    extract::{ConnectInfo, Extension, RawForm, State, rejection::RawFormRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::{fmt, net::SocketAddr};

use super::{
    client_auth::{ClientCredentialError, resolve_client_credentials},
    form,
    response::with_no_store_headers,
    token::decode_access_token,
    token_security::enforce_source_qps_with_policy,
};
use crate::{audit::AuditEvent, error, state::AppState};

#[derive(Deserialize)]
pub struct RevocationRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl fmt::Debug for RevocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationRequest")
            .field("token", &"<redacted>")
            .field("token_type_hint", &self.token_type_hint)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    form: Result<RawForm, RawFormRejection>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    if let Some(response) = enforce_source_qps_with_policy(&state, source_ip.as_deref()).await {
        return with_no_store_headers(response);
    }

    let RawForm(body) = match form {
        Ok(form) => form,
        Err(_) => {
            return with_no_store_headers(error::oauth_bad_request(
                "invalid_request",
                "request body is invalid",
            ));
        }
    };
    let request = match form::deserialize(&body) {
        Some(request) => request,
        None => {
            return with_no_store_headers(error::oauth_bad_request(
                "invalid_request",
                "request body is invalid",
            ));
        }
    };
    with_no_store_headers(revoke_inner(state, headers, request).await)
}

async fn revoke_inner(state: AppState, headers: HeaderMap, request: RevocationRequest) -> Response {
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
        .verify_credentials(
            &credentials.client_id,
            credentials.auth_method,
            credentials.client_secret.as_deref(),
        )
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
    // RFC 7009 treats the hint as a lookup preference, not an exclusive type filter.
    let refresh_first = !matches!(hint, Some("access_token"));
    if refresh_first {
        match try_revoke_refresh_token(&state, &request.token, &credentials.client_id).await {
            Ok(true) => return ().into_response(),
            Ok(false) => {}
            Err(response) => return response,
        }
    }

    let access_token_found = if let Ok(claims) = decode_access_token(
        &state.keys,
        &state.config.issuer_url,
        &credentials.client_id,
        &request.token,
    ) {
        let now = state.clock.now().unix_timestamp();
        if let Ok(expires_at) = i64::try_from(claims.exp) {
            let ttl = expires_at.saturating_sub(now);
            if ttl > 0
                && let Err(store_error) = state.revocations.revoke(&request.token, ttl as u64).await
            {
                tracing::error!(error = %store_error, "failed to revoke access token");
                return error::oauth_temporarily_unavailable();
            }
            if ttl > 0
                && record_revocation_event(
                    &state,
                    Some(&claims.sub),
                    &credentials.client_id,
                    "access_token",
                )
                .await
                .is_err()
            {
                if let Err(error_value) = state.revocations.remove(&request.token).await {
                    tracing::warn!(
                        error = %error_value,
                        "failed to compensate access token revocation after audit persistence failure"
                    );
                }
                return error::oauth_server_error();
            }
        }
        true
    } else {
        false
    };

    if !refresh_first && !access_token_found {
        match try_revoke_refresh_token(&state, &request.token, &credentials.client_id).await {
            Ok(true) => return ().into_response(),
            Ok(false) => {}
            Err(response) => return response,
        }
    }

    ().into_response()
}

async fn try_revoke_refresh_token(
    state: &AppState,
    token: &str,
    client_id: &str,
) -> Result<bool, Response> {
    let refresh = match state.refresh_tokens.find(token).await {
        Ok(Some(refresh)) if refresh.client_id == client_id => refresh,
        Ok(_) => return Ok(false),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to look up refresh token");
            return Err(error::oauth_temporarily_unavailable());
        }
    };

    if let Err(store_error) = state.refresh_tokens.remove(token).await {
        tracing::error!(error = %store_error, "failed to revoke refresh token");
        return Err(error::oauth_temporarily_unavailable());
    }
    if record_revocation_event(state, Some(&refresh.user_id), client_id, "refresh_token")
        .await
        .is_err()
    {
        if let Err(error_value) = state.refresh_tokens.save(&refresh).await {
            tracing::warn!(
                error = %error_value,
                "failed to restore refresh token after audit persistence failure"
            );
        }
        return Err(error::oauth_server_error());
    }

    Ok(true)
}

async fn record_revocation_event(
    state: &AppState,
    actor_id: Option<&str>,
    client_id: &str,
    token_type: &str,
) -> Result<(), crate::audit::AuditError> {
    state
        .audit
        .record_blocking(AuditEvent::new(
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "oauth_client".to_owned()
            },
            actor_id.map(str::to_owned),
            "token_revoke".to_owned(),
            "oauth_token".to_owned(),
            Some(client_id.to_owned()),
            serde_json::json!({"token_type": token_type, "result": "success"}),
        ))
        .await
}
