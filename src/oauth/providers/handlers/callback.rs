use crate::{
    api::extract::RequestIssuer,
    audit::AuditEvent,
    auth_factors::session::clear_pending_login_after_external_success,
    error,
    oauth::{
        providers::{
            domain::is_valid_provider_slug,
            error_helpers::{
                append_external_state_clear, external_binding_failure, external_callback_path,
                external_error, external_error_with_request,
            },
            service::ExternalOAuthError,
            state_store::ExternalLoginStateTake,
        },
        request_binding::{
            PendingRequestBinding, PendingRequestBindingError, bind_pending_request,
        },
    },
    sessions::{cookies, domain::Session},
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;

#[derive(Deserialize)]
pub struct ExternalCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

impl fmt::Debug for ExternalCallbackQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalCallbackQuery")
            .field("code", &self.code.as_ref().map(|_| "<redacted>"))
            .field("state", &self.state.as_ref().map(|_| "<redacted>"))
            .field("error", &self.error)
            .finish()
    }
}

pub async fn external_callback(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    Path(slug): Path<String>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Query(query): Query<ExternalCallbackQuery>,
) -> Response {
    // slug 会拼进 Set-Cookie 的 Path 属性，进入错误处理前必须按 provider slug
    // 规则校验：Axum 的 Path 会做百分号解码，未校验的路径参数（如 `%0d%0a`
    // 解码出的 CR/LF）会让清除状态 Cookie 的失败路径在 HeaderValue 校验处变成
    // 无条件 500（Issue #344）。日志不记录 slug 原值，避免回显攻击者可控的控制字符。
    if !is_valid_provider_slug(&slug) {
        tracing::info!("rejected external OAuth callback with an invalid provider slug");
        return error::not_found(
            "oauth_provider_not_found",
            "external OAuth provider not found",
        );
    }
    let callback_path = external_callback_path(&slug);
    // 登录成功审计需要请求上下文（源 IP / UA），在早退路径之前解析一次（Issue #308）。
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let user_agent = crate::api::user_agent(&headers);
    let Some(returned_state) = query.state.as_deref().filter(|value| !value.is_empty()) else {
        return external_error(&state, &slug, "oauth_login_failed").await;
    };
    let cookie_state =
        cookies::external_state(&headers, returned_state, state.config.cookie_secure)
            .ok()
            .flatten();
    if cookie_state.as_deref() != Some(returned_state) {
        return external_error_with_request(
            &state,
            &slug,
            None,
            Some(returned_state),
            "oauth_login_failed",
        )
        .await;
    }
    let stored_state = match state
        .external_login_states
        .take_for_purpose_and_provider(returned_state, "login", &slug)
        .await
    {
        Ok(ExternalLoginStateTake::Consumed(value)) => value,
        Ok(ExternalLoginStateTake::Mismatch) => {
            // A state sent to another provider slug remains valid for its original
            // callback. Preserve the matching browser cookie with the Redis state.
            return external_error_with_request(&state, &slug, None, None, "oauth_login_failed")
                .await;
        }
        Ok(ExternalLoginStateTake::MissingOrConsumed) => {
            return external_error_with_request(
                &state,
                &slug,
                None,
                Some(returned_state),
                "oauth_login_failed",
            )
            .await;
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to consume external OAuth state");
            return external_error_with_request(
                &state,
                &slug,
                None,
                Some(returned_state),
                "oauth_login_failed",
            )
            .await;
        }
    };
    if query.error.is_some() {
        return external_error_with_request(
            &state,
            &slug,
            stored_state.request_id.as_deref(),
            Some(returned_state),
            "oauth_login_failed",
        )
        .await;
    }
    let Some(code) = query.code.as_deref().filter(|value| !value.is_empty()) else {
        return external_error_with_request(
            &state,
            &slug,
            stored_state.request_id.as_deref(),
            Some(returned_state),
            "oauth_login_failed",
        )
        .await;
    };
    let provider = match state.external_oauth.find(&slug).await {
        Ok(provider) if provider.status == "active" => provider,
        _ => {
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                Some(returned_state),
                "oauth_provider_not_found",
            )
            .await;
        }
    };
    let callback = format!("{}{}", issuer.issuer().as_str(), callback_path);
    // 用发起授权时存入 state 的 verifier 兑换授权码（RFC 7636 §4.5）。
    // 空串表示本次登录未使用 PKCE：provider 关闭了开关，或这是升级前签发的旧 state。
    let token = match state
        .external_oauth
        .exchange_code(&provider, &callback, code, &stored_state.code_verifier)
        .await
    {
        Ok(token) => token,
        Err(error_value) => {
            tracing::info!(error = %error_value, provider = %slug, "external OAuth token exchange failed");
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                Some(returned_state),
                "oauth_login_failed",
            )
            .await;
        }
    };
    let external_user = match state.external_oauth.userinfo(&provider, &token).await {
        Ok(user) => user,
        Err(error_value) => {
            // 未验证邮箱是可解释的用户侧结果，给出专门的错误码；其余原因
            // （远端失败、claim 缺失、provider 配置不可用）保持统一的模糊文案，
            // 不向浏览器泄露外部 IdP 的内部细节。
            let error_code = match &error_value {
                ExternalOAuthError::EmailNotVerified => "oauth_email_unverified",
                _ => "oauth_login_failed",
            };
            tracing::info!(error = %error_value, provider = %slug, "external OAuth userinfo failed");
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                Some(returned_state),
                error_code,
            )
            .await;
        }
    };
    let user_id = match state
        .external_oauth
        .resolve_user(&provider, &external_user)
        .await
    {
        Ok(user_id) => user_id,
        Err(error_value) => {
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                Some(returned_state),
                resolve_error_code(&slug, &error_value),
            )
            .await;
        }
    };
    // 与本地登录共用 SettingsService：缺行走启动配置 SESSION_TTL_SECONDS（#645）。
    let session_lifetime = match state.settings.session_lifetime().await {
        Ok(setting) => setting,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load browser session lifetime setting");
            return error::internal();
        }
    };
    let ttl = std::time::Duration::from_secs(session_lifetime.session_ttl_seconds);
    // 签发时写入 Session；查找用会话自己的窗口，不读当前 Settings（#644）。
    let idle_timeout =
        std::time::Duration::from_secs(session_lifetime.session_idle_timeout_seconds);
    let mut session = match Session::new_at_with_idle_timeout(
        user_id.to_string(),
        ttl,
        idle_timeout,
        state.clock.now(),
    ) {
        Ok(session) => session,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create external OAuth session");
            let mut response = error::internal();
            if let Err(cookie_error) = append_external_state_clear(
                &mut response,
                returned_state,
                state.config.cookie_secure,
            ) {
                tracing::error!(
                    error = %cookie_error,
                    "failed to clear external OAuth state cookie"
                );
            }
            return response;
        }
    };
    if let Err(error_value) = state.sessions.save(&mut session, ttl).await {
        tracing::error!(error = %error_value, "failed to save external OAuth session");
        let mut response = error::internal();
        if let Err(cookie_error) =
            append_external_state_clear(&mut response, returned_state, state.config.cookie_secure)
        {
            tracing::error!(
                error = %cookie_error,
                "failed to clear external OAuth state cookie"
            );
        }
        return response;
    }
    let request_id = stored_state
        .request_id
        .as_deref()
        .filter(|value| !value.is_empty());
    let holder_hash = cookies::extract_authz_holder_cookie_for_secure_transport(
        &headers,
        state.config.cookie_secure,
    )
    .ok()
    .flatten()
    .as_deref()
    .map(cookies::authz_holder_hash);
    if let Some(request_id) = request_id
        && let Err(error_code) = bind_and_audit(
            &state,
            request_id,
            &session,
            holder_hash.as_deref(),
            user_id,
            issuer.generation(),
        )
        .await
    {
        // 绑定失败即登录失败：撤销刚建好的 Session 并清 Cookie，不留下"已登录"副作用。
        return external_binding_failure(
            &state,
            &slug,
            request_id,
            returned_state,
            error_code,
            &session,
        )
        .await;
    }
    if state
        .audit
        .record_blocking(AuditEvent::new(
            "user".to_owned(),
            Some(user_id.to_string()),
            crate::audit::AuditAction::Login,
            "session".to_owned(),
            Some(session.id.to_string()),
            crate::audit::with_request_context(
                serde_json::json!({
                    "result": "success",
                    "channel": "external_oauth",
                    "provider": slug,
                }),
                source_ip.as_deref(),
                user_agent.as_deref(),
            ),
        ))
        .await
        .is_err()
    {
        if let Err(error_value) = state.sessions.revoke(&session.token).await {
            tracing::warn!(
                error = %error_value,
                "failed to compensate external OAuth session after audit persistence failure"
            );
        }
        let mut response = error::internal();
        if let Err(cookie_error) =
            append_external_state_clear(&mut response, returned_state, state.config.cookie_secure)
        {
            tracing::error!(
                error = %cookie_error,
                "failed to clear external OAuth state cookie"
            );
        }
        return response;
    }
    // Session is bound to the pending request above before handing control to the
    // SPA consent screen; otherwise land on the SPA login page.
    let mut response = if let Some(request_id) = request_id {
        Redirect::to(&format!("/oauth/consent?request_id={request_id}")).into_response()
    } else {
        Redirect::to("/login?external=success").into_response()
    };
    if let Err(cookie_error) = cookies::append_login_cookies(
        response.headers_mut(),
        &session.token,
        &session.csrf_token,
        session_lifetime.session_ttl_seconds,
        state.config.cookie_secure,
    ) {
        tracing::error!(error = %cookie_error, "failed to build external OAuth login cookies");
        return cookie_failure_response(&state, &session, returned_state).await;
    }
    if let Err(cookie_error) =
        append_external_state_clear(&mut response, returned_state, state.config.cookie_secure)
    {
        tracing::error!(
            error = %cookie_error,
            "failed to clear external OAuth state cookie"
        );
        return cookie_failure_response(&state, &session, returned_state).await;
    }
    // Session 已经对浏览器生效。残留 MFA ticket 的清理失败不能撤回这次登录。
    clear_pending_login_after_external_success(&state, &headers, &mut response).await;
    response
}

/// 把外部登录建好的 Session 绑定到 pending 授权请求，失败时给出回跳错误码。
///
/// 与 SPA 的 `/bind` 端点共用 [`bind_pending_request`]，因此受控重绑语义一致：
/// holder Cookie 匹配时，此前绑定的会话摘要会被换成这次外部登录的会话（#270）。
/// 这条路径同样把重绑记进审计——授权码最终按重绑后的会话签发，身份变更必须可检索。
async fn bind_and_audit(
    state: &AppState,
    request_id: &str,
    session: &Session,
    holder_hash: Option<&str>,
    user_id: crate::users::domain::UserId,
    issuer_generation: i64,
) -> Result<(), &'static str> {
    match bind_pending_request(
        &state.authorization_requests,
        request_id,
        &session.token,
        holder_hash,
        issuer_generation,
    )
    .await
    {
        Ok(PendingRequestBinding::Unchanged | PendingRequestBinding::Bound) => Ok(()),
        Ok(PendingRequestBinding::Rebound) => {
            state
                .audit
                .record_best_effort(AuditEvent::new(
                    "user".to_owned(),
                    Some(user_id.to_string()),
                    crate::audit::AuditAction::AuthorizationRequestRebound,
                    "oauth_authorization".to_owned(),
                    None,
                    serde_json::json!({"reason": "session_changed", "channel": "external_oauth"}),
                ))
                .await;
            Ok(())
        }
        Err(PendingRequestBindingError::Expired) => Err("oauth_request_expired"),
        Err(
            PendingRequestBindingError::HolderInvalid
            | PendingRequestBindingError::Contended
            | PendingRequestBindingError::Storage,
        ) => Err("oauth_request_binding_failed"),
    }
}

/// 把身份解析失败映射成回跳给 SPA 的错误码。
///
/// 只有可解释的用户侧结果才拿到专属错误码；其余原因归到统一的模糊文案，
/// 避免向浏览器泄露存储状态或外部 IdP 的内部细节。
fn resolve_error_code(slug: &str, error_value: &ExternalOAuthError) -> &'static str {
    match error_value {
        ExternalOAuthError::EmailAlreadyRegistered => "oauth_account_link_required",
        // 纵深防御分支：`userinfo` 已经拦掉未验证邮箱，这里只会在
        // `ExternalUser` 被其他路径构造时触发，仍按未验证邮箱的语义回报。
        ExternalOAuthError::EmailNotVerified => "oauth_email_unverified",
        ExternalOAuthError::EmailNotAllowed => "oauth_login_failed",
        ExternalOAuthError::OwnerBootstrapRequired => "owner_bootstrap_required",
        ExternalOAuthError::UserDisabled => "oauth_login_failed",
        _ => {
            tracing::error!(error = %error_value, provider = %slug, "failed to resolve external OAuth identity");
            "oauth_login_failed"
        }
    }
}

async fn cookie_failure_response(
    state: &AppState,
    session: &Session,
    returned_state: &str,
) -> Response {
    if let Err(revoke_error) = state.sessions.revoke(&session.token).await {
        tracing::warn!(
            error = %revoke_error,
            "failed to compensate external OAuth session after cookie response failure"
        );
    }
    let mut response = error::internal();
    if let Err(cookie_error) =
        append_external_state_clear(&mut response, returned_state, state.config.cookie_secure)
    {
        tracing::error!(
            error = %cookie_error,
            "failed to clear external OAuth state cookie"
        );
    }
    response
}
