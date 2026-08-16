use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use std::fmt;

use super::{
    authorization::{ValidatedAuthorizationRequest, redirect_uri_matches, scopes_are_allowed},
    code::AuthorizationCode,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizationCodeIssueError {
    #[error("the authenticated session is no longer valid")]
    InvalidSession,
    #[error("the OAuth client is invalid")]
    InvalidClient,
    #[error("the authorization request is invalid")]
    InvalidRequest,
    #[error("authorization is temporarily unavailable")]
    TemporarilyUnavailable,
    #[error("authorization failed after validation")]
    ServerError,
}

impl AuthorizationCodeIssueError {
    pub const fn status(self) -> StatusCode {
        match self {
            Self::InvalidSession => StatusCode::UNAUTHORIZED,
            Self::InvalidClient | Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
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
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<AuthorizationCodeIssue, AuthorizationCodeIssueError> {
    match active_user_id(state, &user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(user_id.clone()),
                    crate::audit::AuditAction::AuthorizationDenied,
                    "oauth_authorization".to_owned(),
                    None,
                    crate::audit::with_request_context(
                        serde_json::json!({"reason": "user_disabled"}),
                        source_ip,
                        user_agent,
                    ),
                ))
                .await;
            return Err(AuthorizationCodeIssueError::InvalidSession);
        }
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load OAuth authorization user");
            return Err(AuthorizationCodeIssueError::TemporarilyUnavailable);
        }
    }
    let Some(client) = state
        .clients
        .find_registered(&validated.client_id)
        .await
        .map_err(|error_value| {
            tracing::error!(error = %error_value, "failed to load OAuth client for quota");
            AuthorizationCodeIssueError::TemporarilyUnavailable
        })?
    else {
        return Err(AuthorizationCodeIssueError::InvalidClient);
    };
    if validated.client_id != client.client_id
        || !client
            .redirect_uris
            .iter()
            .any(|uri| redirect_uri_matches(uri, &validated.redirect_uri))
        || !scopes_are_allowed(
            &client,
            &validated.scopes,
            &state.config.client_registration_limits.allowed_scopes,
        )
    {
        return Err(AuthorizationCodeIssueError::InvalidRequest);
    }
    let limits = state
        .settings
        .security_limits()
        .await
        .map_err(|error_value| {
            tracing::error!(error = %error_value, "failed to load OAuth security limits");
            AuthorizationCodeIssueError::TemporarilyUnavailable
        })?;
    let client_id = validated.client_id.clone();
    // 签发时刻必须来自共享时钟：store 保存时用 `self.clock.now()` 计算 Redis TTL，
    // 这里另读墙钟会让注入时钟下「TTL 被夹断为 1 秒」成为真实矛盾。
    let mut code = AuthorizationCode::new_with_nonce_and_ttl_with_session_hash_at(
        validated.client_id,
        validated.redirect_uri.clone(),
        user_id.clone(),
        validated.scopes,
        validated.code_challenge,
        validated.nonce,
        // 授权码绑定签发时的会话摘要：会话撤销后 Token 端点会拒绝兑换。
        validated.session_token_hash,
        limits.authorization_code_ttl_seconds,
        state.clock.now(),
    );
    let state_value = validated.state;
    // 把同意缓存同步到数据库当前的权威状态（Issue #276）。
    //
    // 旧实现在这里删除缓存键。删除只能让下一次判定回源，无法阻止一个「先提交 DB
    // 撤销、后写 Redis」的并发请求随后把陈旧的撤销标记写进来；那个标记会让刚刚
    // 重新授权的用户在 refresh / userinfo 上被持续拒绝。
    //
    // 改为写入带 `state_version` 的围栏值：版本化条件写会拒绝任何版本更低的
    // 迟到写入。失败仍然回滚授权码并返回 503——授权码尚未交给客户端，
    // 此时放弃本次授权不会烧掉任何已发出的凭据。
    if let Err(error_value) = state
        .revocations
        .refresh_consent_cache(&code.user_id, &code.client_id)
        .await
    {
        tracing::error!(error = %error_value, "failed to sync OAuth consent state cache");
        remove_authorization_code_after_failure(state, &code, &client_id, None).await;
        return Err(AuthorizationCodeIssueError::TemporarilyUnavailable);
    }

    // 只有用户自助创建的 Client 计量配额；admin Client（owner_user_id 为空）
    // 和「没有生效套餐」都直接跳过计量，不改变协议错误语义。
    let owner_plan = match client.owner_user_id {
        Some(owner_user_id) => match state.plans.effective_plan_for_user(owner_user_id).await {
            Ok(effective) => effective,
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to load plan for OAuth authorization quota");
                remove_authorization_code_after_failure(state, &code, &client_id, None).await;
                return Err(AuthorizationCodeIssueError::TemporarilyUnavailable);
            }
        },
        None => None,
    };
    let quota_reservation = if let Some(effective) = owner_plan {
        let limits = effective.plan.auth_quota_limits();
        let consumption = match state
            .oauth_quotas
            .consume_with_limits_and_reservation_at(&client_id, limits, state.clock.now())
            .await
        {
            Ok(consumption) => consumption,
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to consume OAuth authorization quota");
                remove_authorization_code_after_failure(state, &code, &client_id, None).await;
                return Err(AuthorizationCodeIssueError::TemporarilyUnavailable);
            }
        };
        match consumption.result {
            QuotaConsumeResult::Allowed => consumption.reservation(),
            QuotaConsumeResult::DailyExceeded | QuotaConsumeResult::MonthlyExceeded => {
                remove_authorization_code_after_failure(state, &code, &client_id, None).await;
                state
                    .audit
                    .record_best_effort(AuditEvent::new(
                        "user".to_owned(),
                        Some(user_id.clone()),
                        crate::audit::AuditAction::RateLimitTriggered,
                        "oauth_quota".to_owned(),
                        None,
                        crate::audit::with_request_context(
                            serde_json::json!({"reason": "oauth_quota"}),
                            source_ip,
                            user_agent,
                        ),
                    ))
                    .await;
                return Ok(AuthorizationCodeIssue::QuotaExceeded);
            }
        }
    } else {
        None
    };
    // 配额消耗成功后，把 reservation 记入「过期未兑换则退款」台账，并把 id
    // 写进授权码 payload：兑换成功时 CAS 会在同一个 Lua 事务里原子取消该条目，
    // 过期未兑换时由后台 worker 退还配额（Issue #341）。
    if let Some(reservation) = quota_reservation.as_ref() {
        code.quota_reservation_id = Some(reservation.id().to_owned());
        if let Err(error_value) = state
            .oauth_quotas
            .schedule_refund(reservation, code.expires_at)
            .await
        {
            tracing::error!(error = %error_value, "failed to schedule OAuth authorization quota refund");
            remove_authorization_code_after_failure(
                state,
                &code,
                &client_id,
                quota_reservation.as_ref(),
            )
            .await;
            return Err(AuthorizationCodeIssueError::TemporarilyUnavailable);
        }
    }
    if let Err(store_error) = state.authorization_codes.save(&code).await {
        tracing::error!(error = %store_error, "failed to store OAuth authorization code");
        // 授权码从未交给客户端：本次签发失败不占用配额，退还 reservation。
        remove_authorization_code_after_failure(
            state,
            &code,
            &client_id,
            quota_reservation.as_ref(),
        )
        .await;
        return Err(AuthorizationCodeIssueError::TemporarilyUnavailable);
    }
    if state
        .audit
        .record_blocking(AuditEvent::new(
            "user".to_owned(),
            Some(code.user_id.clone()),
            crate::audit::AuditAction::AuthorizationCodeIssue,
            "oauth_client".to_owned(),
            Some(code.client_id.clone()),
            crate::audit::with_request_context(
                serde_json::json!({"scopes": code.scopes}),
                source_ip,
                user_agent,
            ),
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
        return Err(AuthorizationCodeIssueError::ServerError);
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
            return Err(AuthorizationCodeIssueError::ServerError);
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
    // Refund only after Redis gives a definitive result. If the operation
    // fails, the code may still exist and remain redeemable, so refunding
    // would let the same authorization consume quota twice.
    match state.authorization_codes.take(&code.value).await {
        Ok(_) => refund_quota_if_consumed(state, client_id, quota_reservation).await,
        Err(error_value) => {
            tracing::error!(
                error = %error_value,
                client_id = %client_id,
                "failed to compensate authorization code; quota refund skipped"
            );
        }
    }
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

pub(crate) fn authorization_code_issue_error_response(
    error_value: AuthorizationCodeIssueError,
) -> Response {
    match error_value {
        AuthorizationCodeIssueError::InvalidSession => error::oauth_unauthorized(
            "invalid_session",
            "the authenticated session is no longer valid",
            "Session realm=\"oauth\"",
        ),
        AuthorizationCodeIssueError::InvalidClient => {
            error::oauth_bad_request("invalid_client", "client is invalid")
        }
        AuthorizationCodeIssueError::InvalidRequest => {
            error::oauth_bad_request("invalid_request", "authorization request is invalid")
        }
        AuthorizationCodeIssueError::TemporarilyUnavailable => {
            error::oauth_temporarily_unavailable()
        }
        AuthorizationCodeIssueError::ServerError => error::oauth_server_error(),
    }
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
        // holder 由 `save_and_redirect_to_ui` 在交给 SPA 之前生成并回填（#115 / #270）。
        // 这里留 None：预授权直通路径不经过 SPA 也不经过绑定端点，不需要 holder。
        holder_hash: None,
    }
}

pub(crate) async fn restore_pending_after_failure(
    state: &AppState,
    pending: &PendingAuthorization,
    remaining_ttl_ms: u64,
) {
    if remaining_ttl_ms == 0 {
        return;
    }
    if let Err(store_error) = state
        .authorization_requests
        .save_limited_with_ttl(pending, remaining_ttl_ms)
        .await
    {
        tracing::error!(error = %store_error, "failed to restore OAuth authorization request");
    }
}

pub async fn issue_authorization_code(
    state: &AppState,
    user_id: String,
    validated: ValidatedAuthorizationRequest,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) -> Response {
    let pending = pending_from_validated(&validated);
    match issue_authorization_code_result(state, user_id, validated, source_ip, user_agent).await {
        Ok(AuthorizationCodeIssue::Redirect(redirect)) => Redirect::to(&redirect).into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => authorization_quota_redirect(&pending),
        Err(error_value) => authorization_code_issue_error_response(error_value),
    }
}
