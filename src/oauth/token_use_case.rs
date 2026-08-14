use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

use super::{
    grant_gate::{GrantGateError, effective_grant_scopes},
    quota::QuotaRefundCancel,
    refresh::RefreshToken,
    session::active_user_epoch,
};
use crate::{clients::service::AuthenticatedClient, config::IssuerUrl, state::AppState};

#[path = "refresh_use_case.rs"]
mod refresh_use_case;
#[path = "token_exchange_audit.rs"]
mod token_exchange_audit;
#[path = "token_use_case_support.rs"]
mod token_use_case_support;
use token_exchange_audit::{exchange_failure, record_token_exchange_success};
pub(crate) use token_use_case_support::{TokenIssueParams, issue_token_response};
use token_use_case_support::{
    authorization_code_session_auth_time, compensate_authorization_code_exchange,
    validate_code_binding,
};

const TOKEN_EXCHANGE_ACTION: &str = "token_exchange";
const TOKEN_EXCHANGE_FAILURE_ACTION: &str = "token_exchange_failure";

#[derive(Deserialize)]
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

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &self.code.as_ref().map(|_| "<redacted>"))
            .field("redirect_uri", &self.redirect_uri)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "code_verifier",
                &self.code_verifier.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Serialize)]
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

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
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
    #[error("OAuth server error")]
    ServerError,
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

    fn server_error() -> Self {
        Self::ServerError
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
    authenticated: AuthenticatedClient,
    issuer: &IssuerUrl,
) -> Result<TokenResponse, OAuthError> {
    let Some(code_value) = request.code.as_deref() else {
        return exchange_failure(
            state,
            None,
            request.client_id.as_deref(),
            "missing_code",
            OAuthError::bad_request("invalid_request", "code is required"),
        )
        .await;
    };
    let Some(redirect_uri) = request.redirect_uri.as_deref() else {
        return exchange_failure(
            state,
            None,
            request.client_id.as_deref(),
            "missing_redirect_uri",
            OAuthError::bad_request("invalid_request", "redirect_uri is required"),
        )
        .await;
    };
    let Some(code_verifier) = request.code_verifier.as_deref() else {
        return exchange_failure(
            state,
            None,
            request.client_id.as_deref(),
            "missing_code_verifier",
            OAuthError::bad_request("invalid_request", "code_verifier is required"),
        )
        .await;
    };
    let code = match state.authorization_codes.find(code_value).await {
        Ok(Some(code)) => code,
        Ok(None) => {
            return exchange_failure(
                state,
                None,
                request.client_id.as_deref(),
                "code_not_found",
                OAuthError::invalid_grant(),
            )
            .await;
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve OAuth authorization code");
            return exchange_failure(
                state,
                None,
                request.client_id.as_deref(),
                "code_lookup_failed",
                OAuthError::temporarily_unavailable(),
            )
            .await;
        }
    };
    let Some(client_id) = request.client_id.as_deref() else {
        return exchange_failure(
            state,
            Some(&code.user_id),
            None,
            "missing_client_id",
            OAuthError::InvalidClient,
        )
        .await;
    };
    if authenticated.client_id() != client_id {
        return exchange_failure(
            state,
            Some(&code.user_id),
            Some(client_id),
            "authenticated_client_mismatch",
            OAuthError::InvalidClient,
        )
        .await;
    }
    if let Err(error) = validate_code_binding(
        client_id,
        redirect_uri,
        code_verifier,
        &code,
        state.clock.now(),
    ) {
        return exchange_failure(
            state,
            Some(&code.user_id),
            Some(client_id),
            "code_binding_invalid",
            error,
        )
        .await;
    }
    // 凭据代际与 active 判定同一次读取（Issue #409）：下面签发 Refresh Token
    // 时会把当前 `session_epoch` stamp 进 payload。之后任何推进 epoch 的撤销
    // 操作（改密 / 管理端 TOTP 重置 / 禁用）都会让这枚 token 在兑换时被拒绝。
    let user_epoch = match active_user_epoch(state, &code.user_id).await {
        Ok(Some(epoch)) => epoch,
        Ok(None) => {
            return exchange_failure(
                state,
                Some(&code.user_id),
                Some(client_id),
                "user_inactive",
                OAuthError::invalid_grant(),
            )
            .await;
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load authorization code user");
            return exchange_failure(
                state,
                Some(&code.user_id),
                Some(client_id),
                "user_lookup_failed",
                OAuthError::temporarily_unavailable(),
            )
            .await;
        }
    };
    // Session binding is intentionally checked before the authorization-code CAS. A failed
    // request must not burn a valid code before binding, expiry, and PKCE all pass.
    let auth_time = match authorization_code_session_auth_time(state, &code).await {
        Ok(auth_time) => auth_time,
        Err(error) => {
            return exchange_failure(
                state,
                Some(&code.user_id),
                Some(client_id),
                "session_validation_failed",
                error,
            )
            .await;
        }
    };
    // 授权码在 TTL 内可能跨越用户撤销授权、管理员禁用 Client 或缩减注册
    // scope。此前这里完全没有同意门禁，撤销应用后仍能换出 AT + RT（Issue
    // #417）；scope 也不复核当前注册集合（Issue #421）。闸门与 refresh /
    // UserInfo 共用同一实现，放在 CAS 之前：授权失效不该先烧掉授权码，存储
    // 故障更不该。
    let scopes = match effective_grant_scopes(state, &code.user_id, client_id, &code.scopes).await {
        Ok(scopes) => scopes,
        Err(gate_error) => {
            let error = match gate_error {
                GrantGateError::Denied(_) => OAuthError::invalid_grant(),
                GrantGateError::Unavailable(_) => OAuthError::temporarily_unavailable(),
            };
            return exchange_failure(
                state,
                Some(&code.user_id),
                Some(client_id),
                gate_error.reason(),
                error,
            )
            .await;
        }
    };
    // Keep this shared row lock until the Refresh Token is indexed in Redis.
    // Secret rotation's UPDATE takes a conflicting row lock, so it either
    // commits first and makes this snapshot stale, or waits and subsequently
    // revokes the token that this request persisted.
    let issuance_guard = match state.clients.acquire_issuance_guard(&authenticated).await {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            return exchange_failure(
                state,
                Some(&code.user_id),
                Some(client_id),
                "client_secret_version_changed",
                OAuthError::InvalidClient,
            )
            .await;
        }
        Err(database_error) => {
            tracing::error!(
                error = %database_error,
                "failed to fence authorization-code token issuance"
            );
            return exchange_failure(
                state,
                Some(&code.user_id),
                Some(client_id),
                "client_secret_version_check_failed",
                OAuthError::temporarily_unavailable(),
            )
            .await;
        }
    };
    // 有计量配额的授权码在签发时登记了「过期未兑换则退款」台账条目；兑换成功
    // 意味着配额应当保留，CAS 脚本在同一原子步骤里取消该条目（Issue #341）。
    // 旧格式在途授权码没有 reservation id，走纯 CAS，行为与历史一致。
    let quota_cancel = code
        .quota_reservation_id
        .as_deref()
        .map(QuotaRefundCancel::for_reservation);
    match state
        .authorization_codes
        .take_if_matches_with_quota_cancel(code_value, &code, quota_cancel)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            if let Err(release_error) = issuance_guard.release().await {
                tracing::warn!(
                    error = %release_error,
                    "failed to release Client credential issuance fence"
                );
            }
            return exchange_failure(
                state,
                Some(&code.user_id),
                Some(client_id),
                "code_consumption_race",
                OAuthError::invalid_grant(),
            )
            .await;
        }
        Err(store_error) => {
            if let Err(release_error) = issuance_guard.release().await {
                tracing::warn!(
                    error = %release_error,
                    "failed to release Client credential issuance fence"
                );
            }
            tracing::error!(error = %store_error, "failed to consume OAuth authorization code");
            return exchange_failure(
                state,
                Some(&code.user_id),
                Some(client_id),
                "code_consume_failed",
                OAuthError::temporarily_unavailable(),
            )
            .await;
        }
    }
    // 后继凭据携带**收窄后**的集合。写回原始 `code.scopes` 会让下一次 refresh
    // 重新带上已经不再注册的 scope，闸门的收窄效果只维持一次兑换（#421）。
    let refresh = RefreshToken::new_at_with_client_secret_version(
        client_id.to_owned(),
        code.user_id.clone(),
        scopes.clone(),
        authenticated.client_secret_version(),
        user_epoch,
        state.clock.now(),
    );
    if let Err(store_error) = state.refresh_tokens.save(&refresh).await {
        if let Err(release_error) = issuance_guard.release().await {
            tracing::warn!(
                error = %release_error,
                "failed to release Client credential issuance fence"
            );
        }
        tracing::error!(error = %store_error, "failed to store refresh token");
        compensate_authorization_code_exchange(state, &code, &refresh.value).await;
        return exchange_failure(
            state,
            Some(&code.user_id),
            Some(client_id),
            "refresh_token_persistence_failed",
            OAuthError::temporarily_unavailable(),
        )
        .await;
    }
    if let Err(release_error) = issuance_guard.release().await {
        tracing::error!(
            error = %release_error,
            client_id = %client_id,
            "failed to release Client credential issuance fence after storing refresh token"
        );
        compensate_authorization_code_exchange(state, &code, &refresh.value).await;
        return exchange_failure(
            state,
            Some(&code.user_id),
            Some(client_id),
            "client_secret_version_fence_release_failed",
            OAuthError::temporarily_unavailable(),
        )
        .await;
    }
    let token = match issue_token_response(
        state,
        TokenIssueParams {
            issuer,
            user_id: &code.user_id,
            client_id,
            scopes: &scopes,
            refresh_token: Some(refresh.value.clone()),
            nonce: code.nonce.as_deref(),
            auth_time,
        },
    )
    .await
    {
        Ok(token) => token,
        Err(error) => {
            compensate_authorization_code_exchange(state, &code, &refresh.value).await;
            return exchange_failure(
                state,
                Some(&code.user_id),
                Some(client_id),
                "token_issuance_failed",
                error,
            )
            .await;
        }
    };
    if let Err(audit_error) =
        record_token_exchange_success(state, &code.user_id, client_id, &scopes).await
    {
        compensate_authorization_code_exchange(state, &code, &refresh.value).await;
        tracing::error!(
            error = %audit_error,
            client_id = %client_id,
            user_id = %code.user_id,
            "failed to record OAuth token exchange audit event"
        );
        return exchange_failure(
            state,
            Some(&code.user_id),
            Some(client_id),
            "success_audit_failed",
            OAuthError::server_error(),
        )
        .await;
    }
    Ok(token)
}

/// Exchange a refresh token after the token endpoint has authenticated the client.
pub async fn exchange_refresh_token(
    state: &AppState,
    issuer: &IssuerUrl,
    request: TokenRequest,
    authenticated: AuthenticatedClient,
) -> Result<TokenResponse, RefreshExchangeError> {
    refresh_use_case::exchange_refresh_token(state, issuer, request, authenticated).await
}

#[cfg(test)]
#[path = "token_use_case_tests.rs"]
mod tests;
