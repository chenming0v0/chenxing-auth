use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;

use super::{
    authorization_decision_use_case::{
        AuthorizationDecision, AuthorizationDecisionCommand, DecisionError, decide_authorization,
    },
    consent::parse_decision,
    request_binding::{
        PendingRequestBinding, PendingRequestBindingError, bind_pending_request,
        discard_issuer_mismatched_pending,
    },
    ui_responses::{DecisionResponse, PendingRequestResponse},
};
use crate::{
    api::extract::{ApiJson, RequestIssuer, SessionRead, SessionWrite},
    audit::AuditEvent,
    error,
    sessions::{cookies, domain::session_token_hash},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct DecisionInput {
    pub decision: String,
}

/// 读取待确认授权请求的展示数据。
///
/// `SessionRead` 只接受 HttpOnly Session Cookie：授权确认页是浏览器场景，
/// 身份不能来自开发期兼容的 `x-chenxing-session` 请求头。
pub async fn inspect_authorization_request(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    session: SessionRead,
    Path(request_id): Path<String>,
) -> Response {
    let pending = match state.authorization_requests.find(&request_id).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return pending_expired(),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to load OAuth authorization request");
            return error::service_unavailable(
                "storage_unavailable",
                "authorization request storage is unavailable",
            );
        }
    };
    if !pending.is_bound_to_issuer_generation(issuer.generation()) {
        return match discard_issuer_mismatched_pending(
            &state.authorization_requests,
            &request_id,
            &pending,
        )
        .await
        {
            Ok(()) => pending_expired(),
            Err(PendingRequestBindingError::Storage) => error::service_unavailable(
                "storage_unavailable",
                "authorization request storage is unavailable",
            ),
            Err(_) => pending_expired(),
        };
    }
    let current_session_hash = session_token_hash(&session.session.token);
    if pending.session_token_hash.as_deref() != Some(current_session_hash.as_str()) {
        return error::unauthorized(
            "invalid_session",
            "authorization request is not bound to this session",
        );
    }
    let Some(client) = (match state.clients.find_registered(&pending.client_id).await {
        Ok(client) => client,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load OAuth UI client");
            return error::service_unavailable(
                "storage_unavailable",
                "OAuth client storage is unavailable",
            );
        }
    }) else {
        return error::bad_request("invalid_client", "client is invalid");
    };
    let Ok(redirect) = url::Url::parse(&pending.redirect_uri) else {
        return error::bad_request("invalid_request", "authorization request is invalid");
    };
    let expires_in = match state
        .authorization_requests
        .remaining_ttl_ms(&pending.request_id)
        .await
    {
        Ok(Some(remaining)) => remaining.div_ceil(1000),
        Ok(None) => return pending_expired(),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to read OAuth authorization request TTL");
            return error::service_unavailable(
                "storage_unavailable",
                "authorization request storage is unavailable",
            );
        }
    };
    (
        axum::http::StatusCode::OK,
        Json(PendingRequestResponse {
            request_id: pending.request_id,
            client_id: pending.client_id,
            client_name: client.client_name,
            redirect_host: redirect.host_str().unwrap_or_default().to_owned(),
            scopes: pending
                .scope
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            expires_in,
        }),
    )
        .into_response()
}

/// 把待确认授权请求绑定到调用者当前的会话。
///
/// 浏览器在还没有会话时就会命中 `/oauth/authorize`，因此 pending 请求以
/// `session_token_hash: None` 落盘并把用户送去 SPA 登录页；SPA 登录完成后调用
/// 本端点补上绑定，`inspect` 与 `decide` 才会接受它。
///
/// # 受控重绑（#270）
///
/// 本端点接受**任何**通过 holder 与会话校验的调用者把请求绑到自己的会话上，
/// 包括请求此前已绑定到别的会话摘要的情况。三层校验缺一不可：
///
/// 1. `SessionWrite`：Session Cookie + CSRF Cookie + `X-CSRF-Token` 三者绑定；
/// 2. holder Cookie 与 pending 记录中的摘要匹配（#115）；
/// 3. CAS 原子写入，与并发的 `bind` / `decide` 不互相覆盖。
///
/// 为什么放开「已绑定就拒绝」：`session_token_hash` 是派生状态而非所有权凭据，
/// holder Cookie 才是所有权凭据。旧规则下会话过期重登或切换账号都会产生新会话，
/// 而 URL 里的 `request_id` 不变，绑定恒定失败 → 前端跟着 401 反复跳登录页。
/// 详见 [`crate::oauth::request_binding`] 的模块文档。
pub async fn bind_authorization_request(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    headers: HeaderMap,
    session: SessionWrite,
    Path(request_id): Path<String>,
) -> Response {
    let holder_hash = cookies::extract_authz_holder_cookie_for_secure_transport(
        &headers,
        state.config.cookie_secure,
    )
    .ok()
    .flatten()
    .as_deref()
    .map(cookies::authz_holder_hash);
    match bind_pending_request(
        &state.authorization_requests,
        &request_id,
        &session.session.token,
        holder_hash.as_deref(),
        issuer.generation(),
    )
    .await
    {
        Ok(PendingRequestBinding::Unchanged | PendingRequestBinding::Bound) => {}
        // 重绑意味着这条授权请求换了持有会话（会话过期重登或切换账号）。
        // 授权码最终按重绑后的会话签发，因此这是一次需要可检索的身份变更。
        Ok(PendingRequestBinding::Rebound) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(session.user_id.to_string()),
                    crate::audit::AuditAction::AuthorizationRequestRebound,
                    "oauth_authorization".to_owned(),
                    None,
                    serde_json::json!({"reason": "session_changed"}),
                ))
                .await;
        }
        Err(PendingRequestBindingError::Expired) => return pending_expired(),
        Err(PendingRequestBindingError::HolderInvalid) => {
            // Cookie 值与摘要都不进日志，只留可检索的事件名与调用者身份。
            tracing::warn!(
                event = "oauth.authz_holder_rejected",
                user_id = %session.user_id,
                "rejected authorization request binding with missing or mismatched holder cookie"
            );
            return error::forbidden(
                "authorization_holder_invalid",
                "authorization request was not initiated by this browser",
            );
        }
        Err(PendingRequestBindingError::Contended) => {
            return error::conflict(
                "authorization_request_conflict",
                "authorization request is being updated concurrently",
            );
        }
        Err(PendingRequestBindingError::Storage) => {
            return error::service_unavailable(
                "storage_unavailable",
                "authorization request storage is unavailable",
            );
        }
    }
    (axum::http::StatusCode::NO_CONTENT, ()).into_response()
}

/// 提交授权确认结果（approve / deny）。
///
/// `SessionWrite` 排在 `Json` 之前：CSRF 与会话校验在请求体反序列化之前完成，
/// 伪造请求的 body 不会被解析。
pub async fn decide_authorization_request(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    session: SessionWrite,
    Path(request_id): Path<String>,
    ApiJson(input): ApiJson<DecisionInput>,
) -> Response {
    // 授权决定写入审计时需要请求上下文（源 IP / UA，Issue #308）。
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let user_agent = crate::api::user_agent(&headers);
    let Some(decision) = parse_decision(&input.decision) else {
        return error::bad_request("invalid_decision", "authorization decision is invalid");
    };
    match decide_authorization(
        &state,
        issuer.snapshot(),
        AuthorizationDecisionCommand::new(
            &request_id,
            session.user_id,
            &session.session.token,
            decision,
            source_ip.as_deref(),
            user_agent.as_deref(),
        ),
    )
    .await
    {
        Ok(outcome) => decision_http_response(outcome),
        Err(error_value) => decision_http_error(error_value),
    }
}

fn decision_http_response(outcome: AuthorizationDecision) -> Response {
    let (decision, redirect_to) = match outcome {
        AuthorizationDecision::Denied { redirect_to } => ("deny", redirect_to),
        AuthorizationDecision::Approved { redirect_to } => ("approve", redirect_to),
    };
    (
        StatusCode::OK,
        Json(DecisionResponse {
            decision,
            redirect_to,
        }),
    )
        .into_response()
}

fn decision_http_error(error_value: DecisionError) -> Response {
    match error_value {
        DecisionError::Expired => pending_expired(),
        DecisionError::InvalidClient => error::bad_request("invalid_client", "client is invalid"),
        DecisionError::InvalidRequest => {
            error::bad_request("invalid_request", "authorization request is invalid")
        }
        DecisionError::SessionMismatch => error::unauthorized(
            "invalid_session",
            "authorization request is not bound to this session",
        ),
        DecisionError::SessionInactive => error::unauthorized(
            "invalid_session",
            "authorization session is no longer valid",
        ),
        DecisionError::Storage => error::service_unavailable(
            "authorization_unavailable",
            "authorization is temporarily unavailable",
        ),
        DecisionError::QuotaExceeded => error::too_many_requests(
            "authorization_unavailable",
            "authorization is temporarily unavailable",
        ),
    }
}

fn pending_expired() -> Response {
    error::bad_request(
        "authorization_request_expired",
        "authorization request is expired",
    )
}
