use axum::{
    extract::{Form, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;

use super::{
    client_auth::{ClientCredentialError, resolve_client_credentials},
    code::{AUTHORIZATION_CODE_TTL_SECONDS, AuthorizationCode},
    pkce::verify_s256,
    refresh::RefreshToken,
    response::{self, issue_token_response},
    session::active_user_id,
};
use crate::{audit::AuditEvent, error, state::AppState};

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

pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Response {
    response::with_no_store_headers(token_inner(state, headers, request).await)
}

async fn token_inner(state: AppState, headers: HeaderMap, mut request: TokenRequest) -> Response {
    let credentials = match resolve_client_credentials(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    ) {
        Ok(credentials) => credentials,
        Err(ClientCredentialError::MultipleMethods | ClientCredentialError::Invalid) => {
            return error::unauthorized("invalid_client", "client credentials are invalid");
        }
        Err(ClientCredentialError::Missing) => {
            return error::unauthorized("invalid_client", "client credentials are required");
        }
    };
    request.client_id = Some(credentials.client_id.clone());
    request.client_secret = Some(credentials.client_secret);
    if let Some(response) = enforce_qps(&state, &credentials.client_id).await {
        return response;
    }
    match request.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(state, request).await,
        "refresh_token" => exchange_refresh_token(state, request).await,
        _ => error::bad_request("unsupported_grant_type", "grant type is unsupported"),
    }
}

async fn exchange_authorization_code(state: AppState, request: TokenRequest) -> Response {
    if let Some(response) = verify_client_credentials(&state, &request).await {
        return response;
    }
    let Some(code_value) = request.code.as_deref() else {
        return error::bad_request("invalid_request", "code is required");
    };
    let Some(redirect_uri) = request.redirect_uri.as_deref() else {
        return error::bad_request("invalid_request", "redirect_uri is required");
    };
    let Some(code_verifier) = request.code_verifier.as_deref() else {
        return error::bad_request("invalid_request", "code_verifier is required");
    };
    let code = match state.authorization_codes.find(code_value).await {
        Ok(Some(code)) => code,
        Ok(None) => return error::bad_request("invalid_grant", "authorization code is invalid"),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve OAuth authorization code");
            return error::internal();
        }
    };
    let client_id = request
        .client_id
        .as_deref()
        .expect("client authentication resolved");
    if code.client_id != client_id || code.redirect_uri != redirect_uri {
        return error::bad_request("invalid_grant", "authorization code binding is invalid");
    }
    if let Err(code_error) = verify_code_is_redeemable(&code) {
        return error::bad_request("invalid_grant", code_error);
    }
    if let Err(pkce_error) = verify_s256(code_verifier, &code.code_challenge) {
        tracing::info!(error = %pkce_error, "OAuth PKCE verification failed");
        return error::bad_request("invalid_grant", "PKCE verification failed");
    }
    match active_user_id(&state, &code.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return error::bad_request("invalid_grant", "authorization code is invalid"),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load authorization code user");
            return error::internal();
        }
    }
    match state
        .authorization_codes
        .take_if_matches(code_value, &code)
        .await
    {
        Ok(true) => {}
        Ok(false) => return error::bad_request("invalid_grant", "authorization code is invalid"),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to consume OAuth authorization code");
            return error::internal();
        }
    }
    let refresh = RefreshToken::new_with_nonce(
        client_id.to_owned(),
        code.user_id.clone(),
        code.scopes.clone(),
        code.nonce.clone(),
    );
    if let Err(store_error) = state.refresh_tokens.save(&refresh).await {
        tracing::error!(error = %store_error, "failed to store refresh token");
        compensate_authorization_code_exchange(&state, &code, &refresh.value).await;
        return error::internal();
    }
    let response = issue_token_response(
        &state,
        &code.user_id,
        client_id,
        &code.scopes,
        Some(refresh.value.clone()),
        code.nonce.as_deref(),
    )
    .await;
    if response.status() != StatusCode::OK {
        compensate_authorization_code_exchange(&state, &code, &refresh.value).await;
    }
    response
}

async fn compensate_authorization_code_exchange(
    state: &AppState,
    code: &AuthorizationCode,
    refresh_value: &str,
) {
    if let Err(store_error) = state.refresh_tokens.remove(refresh_value).await {
        tracing::warn!(
            error = %store_error,
            "failed to remove refresh token during OAuth authorization code compensation"
        );
    }
    let ttl_seconds = authorization_code_restore_ttl(code);
    if let Err(store_error) = state.authorization_codes.restore(code, ttl_seconds).await {
        tracing::warn!(
            error = %store_error,
            "failed to restore OAuth authorization code after token exchange failure"
        );
    }
}

fn authorization_code_restore_ttl(code: &AuthorizationCode) -> u64 {
    let remaining_seconds = (code.expires_at - time::OffsetDateTime::now_utc()).whole_seconds();
    if remaining_seconds > 0 {
        u64::try_from(remaining_seconds).unwrap_or(AUTHORIZATION_CODE_TTL_SECONDS)
    } else {
        1
    }
}

async fn exchange_refresh_token(state: AppState, request: TokenRequest) -> Response {
    if let Some(response) = verify_client_credentials(&state, &request).await {
        return response;
    }
    let Some(refresh_value) = request.refresh_token.as_deref() else {
        return error::bad_request("invalid_request", "refresh_token is required");
    };
    let client_id = request
        .client_id
        .as_deref()
        .expect("client authentication resolved");
    let refresh = match state.refresh_tokens.find(refresh_value).await {
        Ok(Some(refresh)) => refresh,
        Ok(None) => {
            if record_token_event(
                &state,
                None,
                "token_refresh_failure",
                Some(client_id),
                "invalid_token",
            )
            .await
            .is_err()
            {
                return error::internal();
            }
            return error::bad_request("invalid_grant", "refresh token is invalid");
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve refresh token");
            return error::internal();
        }
    };
    if let Err(refresh_error) = refresh.validate(client_id, time::OffsetDateTime::now_utc()) {
        if record_token_event(
            &state,
            Some(&refresh.user_id),
            "token_refresh_failure",
            Some(client_id),
            "invalid_token",
        )
        .await
        .is_err()
        {
            return error::internal();
        }
        return error::bad_request("invalid_grant", refresh_error.to_string());
    }
    match active_user_id(&state, &refresh.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return error::bad_request("invalid_grant", "refresh token is invalid"),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load refresh token user");
            return error::internal();
        }
    }
    let scopes = match request.scope.as_deref() {
        Some(scope) => {
            let requested = scope
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if requested
                .iter()
                .any(|scope| !refresh.scopes.contains(scope))
            {
                return error::bad_request(
                    "invalid_scope",
                    "requested scope exceeds original grant",
                );
            }
            requested
        }
        None => refresh.scopes.clone(),
    };
    let next_refresh = RefreshToken::new_with_nonce(
        client_id.to_owned(),
        refresh.user_id.clone(),
        scopes.clone(),
        refresh.nonce.clone(),
    );
    let response = issue_token_response(
        &state,
        &refresh.user_id,
        client_id,
        &scopes,
        Some(next_refresh.value.clone()),
        refresh.nonce.as_deref(),
    )
    .await;
    if response.status() != StatusCode::OK {
        return response;
    }
    match state
        .refresh_tokens
        .rotate_if_matches(refresh_value, &refresh, &next_refresh)
        .await
    {
        Ok(true) => {
            if record_token_event(
                &state,
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
                return error::internal();
            }
            response
        }
        Ok(false) => {
            if record_token_event(
                &state,
                Some(&refresh.user_id),
                "token_refresh_failure",
                Some(client_id),
                "token_race",
            )
            .await
            .is_err()
            {
                return error::internal();
            }
            error::bad_request("invalid_grant", "refresh token is invalid")
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to atomically rotate refresh token");
            error::internal()
        }
    }
}

/// 按 Client 所属用户的套餐 `max_qps` 做 1 秒窗口限流；不限、无主 Client 或
/// 查询失败时放行（限流是尽力而为的可用性保护，不作为数据正确性依赖）。
async fn enforce_qps(state: &AppState, client_id: &str) -> Option<Response> {
    let client = match state.clients.find_registered(client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return None,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load OAuth client for QPS limit");
            return None;
        }
    };
    let owner_user_id = client.owner_user_id?;
    let effective = match state.plans.effective_plan_for_user(owner_user_id).await {
        Ok(effective) => effective,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load plan for QPS limit");
            return None;
        }
    };
    let max_qps = effective.plan.max_qps?;
    match state.qps.allow(client_id, max_qps.max(1) as u32).await {
        Ok(true) => None,
        Ok(false) => {
            if record_token_event(
                state,
                None,
                "rate_limit_triggered",
                Some(client_id),
                "oauth_qps",
            )
            .await
            .is_err()
            {
                return Some(error::internal());
            }
            Some(error::too_many_requests(
                "qps_exceeded",
                "request rate limit exceeded",
            ))
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "QPS rate limit check failed");
            None
        }
    }
}

async fn verify_client_credentials(state: &AppState, request: &TokenRequest) -> Option<Response> {
    let client_id = request
        .client_id
        .as_deref()
        .expect("client authentication resolved");
    let client_secret = request
        .client_secret
        .as_deref()
        .expect("client authentication resolved");
    match state
        .clients
        .verify_credentials(client_id, client_secret)
        .await
    {
        Ok(true) => None,
        Ok(false) => Some(error::unauthorized(
            "invalid_client",
            "client credentials are invalid",
        )),
        Err(client_error) => {
            tracing::error!(error = %client_error, "failed to verify OAuth client credentials");
            Some(error::internal())
        }
    }
}

fn verify_code_is_redeemable(code: &AuthorizationCode) -> Result<(), &'static str> {
    let mut code = code.clone();
    code.redeem_at(time::OffsetDateTime::now_utc())
        .map_err(|_| "authorization code is expired or already redeemed")
}

async fn record_token_event(
    state: &AppState,
    actor_id: Option<&str>,
    action: &str,
    client_id: Option<&str>,
    reason: &str,
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
            action.to_owned(),
            "oauth_token".to_owned(),
            client_id.map(str::to_owned),
            serde_json::json!({"reason": reason}),
        ))
        .await
}
