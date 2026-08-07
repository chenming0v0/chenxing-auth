use axum::response::{IntoResponse, Redirect, Response};
use std::fmt;

use super::{
    authorization::ValidatedAuthorizationRequest, code::AuthorizationCode,
    consent::PendingAuthorization,
    quota::{QuotaConsumeResult, QuotaReservation},
    session::active_user_id,
};
use crate::audit::AuditEvent;
use crate::{error, state::AppState};

pub enum AuthorizationCodeIssue {
    Redirect(String),
    QuotaExceeded,
}

impl fmt::Debug for AuthorizationCodeIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redirect(_) => formatter
                .debug_tuple("AuthorizationCodeIssue::Redirect")
                .field(&"<redacted>")
                .finish(),
            Self::QuotaExceeded => formatter.write_str("AuthorizationCodeIssue::QuotaExceeded"),
        }
    }
}

pub async fn issue_authorization_code_result(
    state: &AppState,
    user_id: String,
    validated: ValidatedAuthorizationRequest,
) -> Result<AuthorizationCodeIssue, Response> {
    match active_user_id(state, &user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            if record_authorization_event(
                state,
                Some(&user_id),
                "authorization_denied",
                "user_disabled",
            )
            .await
            .is_err()
            {
                return Err(error::oauth_server_error());
            }
            return Err(error::oauth_unauthorized(
                "invalid_session",
                "the authenticated session is no longer valid",
                "Session realm=\"oauth\"",
            ));
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load OAuth authorization user");
            return Err(error::oauth_temporarily_unavailable());
        }
    }
    let Some(client) = state
        .clients
        .find_registered(&validated.client_id)
        .await
        .map_err(|error_value| {
            tracing::error!(error = %error_value, "failed to load OAuth client for quota");
            error::oauth_temporarily_unavailable()
        })?
    else {
        return Err(error::oauth_bad_request(
            "invalid_client",
            "client is invalid",
        ));
    };
    let limits = state
        .settings
        .security_limits()
        .await
        .map_err(|error_value| {
            tracing::error!(error = %error_value, "failed to load OAuth security limits");
            error::oauth_temporarily_unavailable()
        })?;
    let client_id = validated.client_id.clone();
    let code = AuthorizationCode::new_with_nonce_and_ttl_with_session_hash(
        validated.client_id,
        validated.redirect_uri.clone(),
        user_id.clone(),
        validated.scopes,
        validated.code_challenge,
        validated.nonce,
        // 授权码绑定签发时的会话摘要：会话撤销后 Token 端点会拒绝兑换。
        validated.session_token_hash,
        limits.authorization_code_ttl_seconds,
    );
    let state_value = validated.state;
    if let Err(store_error) = state.authorization_codes.save(&code).await {
        tracing::error!(error = %store_error, "failed to store OAuth authorization code");
        return Err(error::oauth_temporarily_unavailable());
    }
    if let Err(error_value) = state
        .revocations
        .clear_consent(&code.user_id, &code.client_id)
        .await
    {
        tracing::error!(error = %error_value, "failed to clear OAuth consent revocation marker");
        remove_authorization_code_after_failure(state, &code, &client_id, None).await;
        return Err(error::oauth_temporarily_unavailable());
    }

    // 只有用户自助创建的 Client 计量配额；admin Client（owner_user_id 为空）
    // 和「没有生效套餐」都直接跳过计量，不改变协议错误语义。
    let owner_plan = match client.owner_user_id {
        Some(owner_user_id) => match state.plans.effective_plan_for_user(owner_user_id).await {
            Ok(effective) => effective,
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to load plan for OAuth authorization quota");
                remove_authorization_code_after_failure(state, &code, &client_id, None).await;
                return Err(error::oauth_temporarily_unavailable());
            }
        },
        None => None,
    };
    let quota_reservation = if let Some(effective) = owner_plan {
        let limits = effective.plan.auth_quota_limits();
        let consumption = match state
            .oauth_quotas
            .consume_with_limits_and_reservation(&client_id, limits)
            .await
        {
            Ok(consumption) => consumption,
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to consume OAuth authorization quota");
                remove_authorization_code_after_failure(state, &code, &client_id, None).await;
                return Err(error::oauth_temporarily_unavailable());
            }
        };
        match consumption.result {
            QuotaConsumeResult::Allowed => consumption.reservation(),
            QuotaConsumeResult::DailyExceeded | QuotaConsumeResult::MonthlyExceeded => {
                remove_authorization_code_after_failure(state, &code, &client_id, None).await;
                if record_authorization_event(
                    state,
                    Some(&user_id),
                    "rate_limit_triggered",
                    "oauth_quota",
                )
                .await
                .is_err()
                {
                    return Err(error::oauth_server_error());
                }
                return Ok(AuthorizationCodeIssue::QuotaExceeded);
            }
        }
    } else {
        None
    };
    if state
        .audit
        .record(AuditEvent::new(
            "user".to_owned(),
            Some(code.user_id.clone()),
            "authorization_code_issue".to_owned(),
            "oauth_client".to_owned(),
            Some(code.client_id.clone()),
            serde_json::json!({"scopes": code.scopes}),
        ))
        .await
        .is_err()
    {
        remove_authorization_code_after_failure(
            state,
            &code,
            &client_id,
            quota_reservation.as_ref(),
        )
        .await;
        return Err(error::oauth_server_error());
    }

    let mut redirect_uri = match url::Url::parse(&validated.redirect_uri) {
        Ok(uri) => uri,
        Err(parse_error) => {
            remove_authorization_code_after_failure(
                state,
                &code,
                &client_id,
                quota_reservation.as_ref(),
            )
            .await;
            tracing::error!(error = %parse_error, "validated redirect URI could not be parsed");
            return Err(error::oauth_server_error());
        }
    };
    redirect_uri
        .query_pairs_mut()
        .append_pair("code", &code.value)
        .append_pair("state", &state_value);

    Ok(AuthorizationCodeIssue::Redirect(redirect_uri.to_string()))
}

async fn remove_authorization_code_after_failure(
    state: &AppState,
    code: &AuthorizationCode,
    client_id: &str,
    quota_reservation: Option<&QuotaReservation>,
) {
    if let Err(error_value) = state.authorization_codes.take(&code.value).await {
        tracing::warn!(
            error = %error_value,
            "failed to compensate authorization code after authorization failure"
        );
    }
    refund_quota_if_consumed(state, client_id, quota_reservation).await;
}

async fn refund_quota_if_consumed(
    state: &AppState,
    client_id: &str,
    reservation: Option<&QuotaReservation>,
) {
    let Some(reservation) = reservation else {
        return;
    };
    if let Err(error_value) = state.oauth_quotas.refund(reservation).await {
        tracing::warn!(
            client_id = %client_id,
            error = %error_value,
            "failed to refund OAuth authorization quota"
        );
    }
}

async fn record_authorization_event(
    state: &AppState,
    actor_id: Option<&str>,
    action: &str,
    reason: &str,
) -> Result<(), crate::audit::AuditError> {
    state
        .audit
        .record(AuditEvent::new(
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "anonymous".to_owned()
            },
            actor_id.map(str::to_owned),
            action.to_owned(),
            "oauth_authorization".to_owned(),
            None,
            serde_json::json!({"reason": reason}),
        ))
        .await
}

pub fn validated_pending_request(pending: PendingAuthorization) -> ValidatedAuthorizationRequest {
    ValidatedAuthorizationRequest {
        client_id: pending.client_id,
        redirect_uri: pending.redirect_uri,
        scopes: pending
            .scope
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        state: pending.state,
        nonce: pending.nonce,
        code_challenge: pending.code_challenge,
        owner_user_id: None,
        // Pending 请求已经绑定了会话摘要，必须原样带下去，否则授权码丢失会话绑定。
        session_token_hash: pending.session_token_hash,
    }
}

pub(crate) fn authorization_quota_redirect(pending: &PendingAuthorization) -> Response {
    let Some(mut redirect) = url::Url::parse(&pending.redirect_uri).ok() else {
        return error::oauth_server_error();
    };
    redirect
        .query_pairs_mut()
        .append_pair("error", "temporarily_unavailable")
        .append_pair(
            "error_description",
            "authorization is temporarily unavailable",
        )
        .append_pair("state", &pending.state);
    Redirect::to(redirect.as_str()).into_response()
}

/// `validated_pending_request` 的反向路径：会话绑定统一从
/// `ValidatedAuthorizationRequest::session_token_hash` 读取，不再另开参数，
/// 避免两个来源不一致时静默丢掉绑定。
pub(crate) fn pending_from_validated(
    request: &ValidatedAuthorizationRequest,
) -> PendingAuthorization {
    PendingAuthorization {
        request_id: uuid::Uuid::new_v4().to_string(),
        client_id: request.client_id.clone(),
        redirect_uri: request.redirect_uri.clone(),
        scope: request.scopes.join(" "),
        state: request.state.clone(),
        nonce: request.nonce.clone(),
        code_challenge: request.code_challenge.clone(),
        code_challenge_method: "S256".to_owned(),
        session_token_hash: request.session_token_hash.clone(),
        // 持有者绑定只在未登录路径上有意义：已有会话的请求直接进入授权确认
        // 或预授权直通，不经过绑定端点。未登录路径由 `save_and_redirect_to_login`
        // 生成 holder 并回填这个字段（#115）。
        holder_hash: None,
    }
}

pub(crate) async fn restore_pending_after_failure(
    state: &AppState,
    pending: &PendingAuthorization,
) {
    if let Err(store_error) = state.authorization_requests.save(pending).await {
        tracing::error!(error = %store_error, "failed to restore OAuth authorization request");
    }
}

pub async fn issue_authorization_code(
    state: &AppState,
    user_id: String,
    validated: ValidatedAuthorizationRequest,
) -> Response {
    let pending = pending_from_validated(&validated);
    match issue_authorization_code_result(state, user_id, validated).await {
        Ok(AuthorizationCodeIssue::Redirect(redirect)) => Redirect::to(&redirect).into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => authorization_quota_redirect(&pending),
        Err(response) => response,
    }
}
