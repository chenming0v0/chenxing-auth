use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;

use super::{
    authorization::{
        AuthorizationRequest, redirect_uri_matches, validate_authorization_request_with_allowlist,
    },
    consent::{ConsentDecision, PendingAuthorization, parse_decision},
    handlers::{AuthorizationCodeIssue, issue_authorization_code_result},
    request_binding::{PendingRequestBinding, PendingRequestBindingError, bind_pending_request},
    session::session_for_headers,
    ui_responses::{DecisionResponse, PendingRequestResponse},
};
use crate::{
    api::extract::{ApiJson, SessionRead, SessionWrite},
    audit::AuditEvent,
    clients::domain::canonicalize_redirect_uri,
    consents::ConsentServiceError,
    error,
    sessions::{
        cookies,
        domain::{Session, session_token_hash},
    },
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
    let limits = match state.settings.security_limits().await {
        Ok(limits) => limits,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load OAuth security limits");
            return error::service_unavailable(
                "settings_unavailable",
                "authorization settings are unavailable",
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
            expires_in: limits.pending_request_ttl_seconds,
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
    let Some(pending) = (match state.authorization_requests.find(&request_id).await {
        Ok(pending) => pending,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to load OAuth authorization request");
            return error::service_unavailable(
                "storage_unavailable",
                "authorization request storage is unavailable",
            );
        }
    }) else {
        return pending_expired();
    };
    let current_session_hash = session_token_hash(&session.session.token);
    if pending.session_token_hash.as_deref() != Some(current_session_hash.as_str()) {
        return error::unauthorized(
            "invalid_session",
            "authorization request is not bound to this session",
        );
    }
    if matches!(decision, ConsentDecision::Deny) {
        // A pending request may outlive a Client update. Never return a denial redirect
        // to a URI that is no longer registered; approve already revalidates the full
        // authorization request, so deny must enforce the same redirect trust boundary.
        let Some(client) = (match state.clients.find_registered(&pending.client_id).await {
            Ok(client) => client,
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to load OAuth client for denial redirect");
                return error::service_unavailable(
                    "client_unavailable",
                    "OAuth client storage is unavailable",
                );
            }
        }) else {
            return error::bad_request("invalid_client", "client is invalid");
        };
        if canonicalize_redirect_uri(&pending.redirect_uri).is_none_or(|redirect_uri| {
            !client
                .redirect_uris
                .iter()
                .any(|registered| redirect_uri_matches(registered, &redirect_uri))
        }) {
            return error::bad_request("invalid_request", "authorization request is invalid");
        }
        let Some(consumed) = (match state
            .authorization_requests
            .take_if_matches_with_ttl(&request_id, &pending)
            .await
        {
            Ok(consumed) => consumed,
            Err(store_error) => {
                tracing::error!(error = %store_error, "failed to consume denied OAuth request");
                return error::service_unavailable(
                    "storage_unavailable",
                    "authorization request storage is unavailable",
                );
            }
        }) else {
            return pending_expired();
        };
        let pending = consumed.request;
        state
            .audit
            .record_best_effort(AuditEvent::new(
                "user".to_owned(),
                Some(session.user_id.to_string()),
                crate::audit::AuditAction::AuthorizationDenied,
                "oauth_authorization".to_owned(),
                Some(pending.client_id.clone()),
                crate::audit::with_request_context(
                    serde_json::json!({"reason": "user_denied"}),
                    source_ip.as_deref(),
                    user_agent.as_deref(),
                ),
            ))
            .await;
        return match error_redirect(&pending, &client) {
            Some(redirect_to) => (
                axum::http::StatusCode::OK,
                Json(DecisionResponse {
                    decision: "deny",
                    redirect_to,
                }),
            )
                .into_response(),
            None => error::bad_request("invalid_request", "authorization request is invalid"),
        };
    }
    let validated = match validated_pending(&state, &pending).await {
        Ok(validated) => validated,
        Err(response) => return response,
    };
    let Some(consumed) = (match state
        .authorization_requests
        .take_if_matches_with_ttl(&request_id, &pending)
        .await
    {
        Ok(consumed) => consumed,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to consume approved OAuth request");
            return error::service_unavailable(
                "storage_unavailable",
                "authorization request storage is unavailable",
            );
        }
    }) else {
        return pending_expired();
    };
    if let Err(response) = session_still_active(&state, &headers, &session.session).await {
        restore_pending(&state, &consumed.request, consumed.remaining_ttl_ms).await;
        return response;
    }
    // `save` 返回本次重新授权的 `state_version`（Issue #276）。这里刻意不用它写缓存：
    // 紧随其后的 `issue_authorization_code_result` 会按数据库权威状态同步缓存围栏，
    // 两处都写只会让「谁的版本更新」多一个来源，而条件写的结论完全相同。
    if let Err(error_value) = state
        .consents
        .save(
            session.user_id,
            &consumed.request.client_id,
            &validated.scopes,
        )
        .await
    {
        // ClientNotFound 是内部一致性错误：validated_pending 已确认过 client 存在
        let response = match error_value {
            ConsentServiceError::ClientNotFound => {
                tracing::error!(
                    client_id = %consumed.request.client_id,
                    user_id = %session.user_id,
                    "consent save rejected: OAuth client no longer exists"
                );
                error::internal()
            }
            ConsentServiceError::Database(database_error) => {
                tracing::error!(error = %database_error, "failed to save JSON OAuth consent");
                error::service_unavailable("consent_unavailable", "consent storage is unavailable")
            }
        };
        restore_pending(&state, &consumed.request, consumed.remaining_ttl_ms).await;
        return response;
    }
    match issue_authorization_code_result(
        &state,
        session.user_id.to_string(),
        validated,
        source_ip.as_deref(),
        user_agent.as_deref(),
    )
    .await
    {
        Ok(AuthorizationCodeIssue::Redirect(redirect_to)) => (
            axum::http::StatusCode::OK,
            Json(DecisionResponse {
                decision: "approve",
                redirect_to,
            }),
        )
            .into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => {
            restore_pending(&state, &consumed.request, consumed.remaining_ttl_ms).await;
            error::too_many_requests(
                "authorization_unavailable",
                "authorization is temporarily unavailable",
            )
        }
        Err(response) => {
            restore_pending(&state, &consumed.request, consumed.remaining_ttl_ms).await;
            let _ = response;
            error::service_unavailable(
                "authorization_unavailable",
                "authorization is temporarily unavailable",
            )
        }
    }
}

async fn validated_pending(
    state: &AppState,
    pending: &PendingAuthorization,
) -> Result<super::authorization::ValidatedAuthorizationRequest, Response> {
    let Some(client) = state
        .clients
        .find_registered(&pending.client_id)
        .await
        .map_err(|error_value| {
            tracing::error!(error = %error_value, "failed to load OAuth client for consent");
            error::service_unavailable("client_unavailable", "OAuth client storage is unavailable")
        })?
    else {
        return Err(error::bad_request("invalid_client", "client is invalid"));
    };
    let mut validated = validate_authorization_request_with_allowlist(
        &client,
        AuthorizationRequest {
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            response_type: "code".to_owned(),
            scope: pending.scope.clone(),
            state: Some(pending.state.clone()),
            nonce: pending.nonce.clone(),
            code_challenge: Some(pending.code_challenge.clone()),
            code_challenge_method: Some(pending.code_challenge_method.clone()),
        },
        &state.config.client_registration_limits.allowed_scopes,
    )
    .map_err(|_| error::bad_request("invalid_request", "authorization request is invalid"))?;
    // 调用方已校验 pending 绑定的会话就是当前会话，授权码必须继承该绑定，
    // 否则用户登出后授权码在 TTL 内仍能兑换 token。
    validated.session_token_hash = pending.session_token_hash.clone();
    Ok(validated)
}

pub(super) fn error_redirect(
    pending: &PendingAuthorization,
    client: &super::authorization::RegisteredClient,
) -> Option<String> {
    let redirect_uri = canonicalize_redirect_uri(&pending.redirect_uri)?;
    if !client
        .redirect_uris
        .iter()
        .any(|registered| redirect_uri_matches(registered, &redirect_uri))
    {
        return None;
    }
    let mut redirect = url::Url::parse(&redirect_uri).ok()?;
    redirect
        .query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("state", &pending.state);
    Some(redirect.to_string())
}

/// 授权码签发前重新确认会话仍然有效。
///
/// 提取器只在请求进入时校验一次身份；pending 请求被原子消费之后、授权码签发之前
/// 会话可能已被撤销或用户被停用，这里再查一次以避免把授权码发给已失效的会话。
async fn session_still_active(
    state: &AppState,
    headers: &HeaderMap,
    expected: &Session,
) -> Result<(), Response> {
    match session_for_headers(state, headers).await {
        Ok(Some(session)) if session.token == expected.token => Ok(()),
        Ok(_) => Err(error::unauthorized(
            "invalid_session",
            "authorization session is no longer valid",
        )),
        Err(session_error) => {
            tracing::error!(error = %session_error, "OAuth session revalidation failed");
            Err(error::service_unavailable(
                "session_unavailable",
                "session storage is unavailable",
            ))
        }
    }
}

async fn restore_pending(state: &AppState, pending: &PendingAuthorization, remaining_ttl_ms: u64) {
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

fn pending_expired() -> Response {
    error::bad_request(
        "authorization_request_expired",
        "authorization request is expired",
    )
}
