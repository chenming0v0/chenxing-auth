use axum::{
    extract::{Form, State, rejection::FormRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use super::{
    client_auth::{ClientCredentialError, resolve_client_credentials},
    response::with_no_store_headers,
    token::decode_access_token,
};
use crate::{audit::AuditEvent, error, state::AppState};

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
    form: Result<Form<RevocationRequest>, FormRejection>,
) -> Response {
    let Form(request) = match form {
        Ok(form) => form,
        Err(_) => {
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
    if matches!(hint, Some("refresh_token") | None) {
        match state.refresh_tokens.find(&request.token).await {
            Ok(Some(refresh)) if refresh.client_id == credentials.client_id => {
                if let Err(store_error) = state.refresh_tokens.remove(&request.token).await {
                    tracing::error!(error = %store_error, "failed to revoke refresh token");
                    return error::oauth_temporarily_unavailable();
                }
                if record_revocation_event(
                    &state,
                    Some(&refresh.user_id),
                    &credentials.client_id,
                    "refresh_token",
                )
                .await
                .is_err()
                {
                    if let Err(error_value) = state.refresh_tokens.save(&refresh).await {
                        tracing::warn!(
                            error = %error_value,
                            "failed to restore refresh token after audit persistence failure"
                        );
                    }
                    return error::oauth_server_error();
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
    }

    ().into_response()
}

async fn record_revocation_event(
    state: &AppState,
    actor_id: Option<&str>,
    client_id: &str,
    token_type: &str,
) -> Result<(), crate::audit::AuditError> {
    state
        .audit
        .record(AuditEvent::new(
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
