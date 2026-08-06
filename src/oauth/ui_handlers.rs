use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    authorization::{AuthorizationRequest, validate_authorization_request},
    consent::{ConsentDecision, PendingAuthorization, parse_decision},
    handlers::{AuthorizationCodeIssue, issue_authorization_code_result},
    session::session_for_headers,
};
use crate::{
    audit::AuditEvent,
    consents::ConsentServiceError,
    error,
    sessions::{
        cookies,
        domain::{Session, session_token_hash},
    },
    state::AppState,
    users::domain::UserId,
};

#[derive(Debug, Serialize)]
struct PendingRequestResponse {
    request_id: String,
    client_id: String,
    client_name: String,
    redirect_host: String,
    scopes: Vec<String>,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct DecisionInput {
    pub decision: String,
}

#[derive(Debug, Serialize)]
struct DecisionResponse {
    decision: &'static str,
    redirect_to: String,
}

struct UserContext {
    user_id: UserId,
    session: Session,
}

pub async fn inspect_authorization_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Response {
    let context = match current_user(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let pending = match state.authorization_requests.find(&request_id).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return pending_expired(),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to load OAuth authorization request");
            return error::oauth_temporarily_unavailable();
        }
    };
    let current_session_hash = session_token_hash(&context.session.token);
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
            return error::oauth_temporarily_unavailable();
        }
    }) else {
        return error::oauth_bad_request("invalid_client", "client is invalid");
    };
    let Ok(redirect) = url::Url::parse(&pending.redirect_uri) else {
        return error::oauth_bad_request("invalid_request", "authorization request is invalid");
    };
    let limits = match state.settings.security_limits().await {
        Ok(limits) => limits,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load OAuth security limits");
            return error::oauth_temporarily_unavailable();
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

/// Bind a pending authorization request to the caller's session.
///
/// The browser hits `/oauth/authorize` before any session exists, so the pending
/// request is created with `session_token_hash: None` and the user is sent to the SPA
/// login page. Once the SPA logs in over JSON, it calls this endpoint so the
/// pending request is tied to the freshly-issued session — after which `inspect`
/// and `decide` accept it. Mirrors the binding the server-rendered
/// `complete_browser_login` used to perform.
///
/// 绑定前必须通过授权请求持有者 Cookie 校验（#115）：仅凭有效会话 + `request_id`
/// 不足以认领一条 pending 请求，否则拿到泄露 `request_id` 的攻击者可以把受害者
/// 的授权请求绑到自己的会话上并批准，使受害者登录进攻击者账号。
pub async fn bind_authorization_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Response {
    let context = match current_user(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !csrf_valid(&headers, &context.session) {
        return error::bad_request("csrf_invalid", "CSRF token is invalid");
    }
    let Some(mut pending) = (match state.authorization_requests.find(&request_id).await {
        Ok(pending) => pending,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to load OAuth authorization request");
            return error::oauth_temporarily_unavailable();
        }
    }) else {
        return pending_expired();
    };
    // 持有者校验放在会话检查之前：包括幂等重试在内的每一次绑定调用都必须证明
    // 自己就是发起授权的那个浏览器。这是叠加在 CSRF 校验之上的一层，
    // 两者都必须通过。Cookie 值不进日志。
    if !authz_holder_valid(&headers, &pending) {
        tracing::warn!(
            event = "oauth.authz_holder_rejected",
            request_id = %request_id,
            user_id = %context.user_id,
            "rejected authorization request binding with missing or mismatched holder cookie"
        );
        return error::forbidden(
            "authorization_holder_invalid",
            "authorization request was not initiated by this browser",
        );
    }
    // Only allow binding an unbound request, or re-binding one already owned by
    // this same session (idempotent retry). Refuse to steal another session's request.
    let current_session_hash = session_token_hash(&context.session.token);
    match pending.session_token_hash.as_deref() {
        None => {}
        Some(existing) if existing == current_session_hash => {
            return (axum::http::StatusCode::NO_CONTENT, ()).into_response();
        }
        Some(_) => {
            return error::unauthorized(
                "invalid_session",
                "authorization request is bound to another session",
            );
        }
    }
    let original_pending = pending.clone();
    pending.session_token_hash = Some(current_session_hash);
    match state
        .authorization_requests
        .replace_if_matches(&request_id, &original_pending, &pending)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return error::unauthorized(
                "invalid_session",
                "authorization request is bound to another session",
            );
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to bind authorization request to session");
            return error::oauth_temporarily_unavailable();
        }
    }
    (axum::http::StatusCode::NO_CONTENT, ()).into_response()
}

pub async fn decide_authorization_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(input): Json<DecisionInput>,
) -> Response {
    let context = match current_user(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !csrf_valid(&headers, &context.session) {
        return error::bad_request("csrf_invalid", "CSRF token is invalid");
    }
    let Some(decision) = parse_decision(&input.decision) else {
        return error::bad_request("invalid_decision", "authorization decision is invalid");
    };
    let Some(pending) = (match state.authorization_requests.find(&request_id).await {
        Ok(pending) => pending,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to load OAuth authorization request");
            return error::oauth_temporarily_unavailable();
        }
    }) else {
        return pending_expired();
    };
    let current_session_hash = session_token_hash(&context.session.token);
    if pending.session_token_hash.as_deref() != Some(current_session_hash.as_str()) {
        return error::unauthorized(
            "invalid_session",
            "authorization request is not bound to this session",
        );
    }
    if matches!(decision, ConsentDecision::Deny) {
        let Some(pending) = (match state
            .authorization_requests
            .take_if_matches(&request_id, &pending)
            .await
        {
            Ok(pending) => pending,
            Err(store_error) => {
                tracing::error!(error = %store_error, "failed to consume denied OAuth request");
                return error::oauth_temporarily_unavailable();
            }
        }) else {
            return pending_expired();
        };
        if state
            .audit
            .record(AuditEvent::new(
                "user".to_owned(),
                Some(context.user_id.to_string()),
                "authorization_denied".to_owned(),
                "oauth_authorization".to_owned(),
                Some(pending.client_id.clone()),
                serde_json::json!({"reason": "user_denied"}),
            ))
            .await
            .is_err()
        {
            return error::internal();
        }
        return match error_redirect(&pending) {
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
        .take_if_matches(&request_id, &pending)
        .await
    {
        Ok(consumed) => consumed,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to consume approved OAuth request");
            return error::oauth_temporarily_unavailable();
        }
    }) else {
        return pending_expired();
    };
    if let Err(response) = session_still_active(&state, &headers, &context.session).await {
        restore_pending(&state, &consumed).await;
        return response;
    }
    if let Err(error_value) = state
        .consents
        .save(context.user_id, &consumed.client_id, &validated.scopes)
        .await
    {
        // ClientNotFound 是内部一致性错误：validated_pending 已确认过 client 存在
        let response = match error_value {
            ConsentServiceError::ClientNotFound => {
                tracing::error!(
                    client_id = %consumed.client_id,
                    user_id = %context.user_id,
                    "consent save rejected: OAuth client no longer exists"
                );
                error::oauth_server_error()
            }
            ConsentServiceError::Database(database_error) => {
                tracing::error!(error = %database_error, "failed to save JSON OAuth consent");
                error::oauth_temporarily_unavailable()
            }
        };
        restore_pending(&state, &consumed).await;
        return response;
    }
    match issue_authorization_code_result(&state, context.user_id.to_string(), validated).await {
        Ok(AuthorizationCodeIssue::Redirect(redirect_to)) => (
            axum::http::StatusCode::OK,
            Json(DecisionResponse {
                decision: "approve",
                redirect_to,
            }),
        )
            .into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => {
            restore_pending(&state, &consumed).await;
            error::oauth_too_many_requests(
                "temporarily_unavailable",
                "authorization is temporarily unavailable",
            )
        }
        Err(response) => {
            restore_pending(&state, &consumed).await;
            response
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
            error::oauth_temporarily_unavailable()
        })?
    else {
        return Err(error::oauth_bad_request(
            "invalid_client",
            "client is invalid",
        ));
    };
    let mut validated = validate_authorization_request(
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
    )
    .map_err(|_| error::oauth_bad_request("invalid_request", "authorization request is invalid"))?;
    // 调用方已校验 pending 绑定的会话就是当前会话，授权码必须继承该绑定，
    // 否则用户登出后授权码在 TTL 内仍能兑换 token。
    validated.session_token_hash = pending.session_token_hash.clone();
    Ok(validated)
}

fn error_redirect(pending: &PendingAuthorization) -> Option<String> {
    let mut redirect = url::Url::parse(&pending.redirect_uri).ok()?;
    redirect
        .query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("state", &pending.state);
    Some(redirect.to_string())
}

async fn current_user(state: &AppState, headers: &HeaderMap) -> Result<UserContext, Response> {
    let session = match session_for_headers(state, headers).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return Err(error::unauthorized(
                "login_required",
                "an authenticated session is required",
            ));
        }
        Err(session_error) => {
            tracing::error!(error = %session_error, "OAuth session lookup failed");
            return Err(error::oauth_temporarily_unavailable());
        }
    };
    let user_id = session
        .user_id
        .parse::<UserId>()
        .map_err(|_| error::unauthorized("invalid_session", "user session is invalid"))?;
    Ok(UserContext { user_id, session })
}

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
            Err(error::oauth_temporarily_unavailable())
        }
    }
}

async fn restore_pending(state: &AppState, pending: &PendingAuthorization) {
    if let Err(store_error) = state.authorization_requests.save(pending).await {
        tracing::error!(error = %store_error, "failed to restore OAuth authorization request");
    }
}

fn pending_expired() -> Response {
    error::bad_request(
        "authorization_request_expired",
        "authorization request is expired",
    )
}

fn csrf_valid(headers: &HeaderMap, session: &Session) -> bool {
    let Some(cookie) = cookies::csrf_cookie(headers) else {
        return false;
    };
    let Some(header) = cookies::csrf_token(headers) else {
        return false;
    };
    cookie == header && session.validates_csrf(&header)
}

/// 校验授权请求持有者 Cookie（#115）：
/// - Cookie 存在 且 SHA-256(cookie值) == pending 中存储的哈希 → 通过
/// - Cookie 不存在 或 pending 中无 holder_hash（旧记录）→ 拒绝（fail-secure）
///
/// 旧记录无 holder_hash 意味着升级前创建的授权请求：拒绝是有意为之，
/// 用户重新发起授权即可获得完整保护。不留「无 holder 即放行」的绕过窗口。
fn authz_holder_valid(headers: &HeaderMap, pending: &PendingAuthorization) -> bool {
    match (
        cookies::extract_authz_holder_cookie(headers).as_deref(),
        pending.holder_hash.as_deref(),
    ) {
        (Some(cookie_value), Some(stored_hash)) => {
            cookies::authz_holder_hash(cookie_value) == stored_hash
        }
        _ => false,
    }
}
