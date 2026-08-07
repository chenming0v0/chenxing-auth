use crate::{
    audit::AuditEvent,
    auth_limiter::MissingSourceIpPolicy,
    error,
    oauth::consent::pending_request_exists,
    oauth::providers::{
        client_pkce::generate_code_verifier,
        error_helpers::{
            append_external_state_clear, external_callback_path, external_error,
            external_error_with_request, external_error_with_session, external_error_with_state,
        },
        provider_pending::{PendingRequestBindingError, bind_pending_request},
        service::ExternalOAuthError,
        state_store::ExternalLoginState,
    },
    sessions::{cookies, domain::Session},
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Deserialize)]
pub struct ExternalLoginQuery {
    pub request_id: Option<String>,
}

/// Public-facing view of an external identity provider: only what the login page
/// needs to render a button. Deliberately omits endpoints, client_id and claims.
#[derive(Debug, serde::Serialize)]
pub struct PublicProvider {
    pub slug: String,
    pub name: String,
}

/// Lists active external OAuth providers for the SPA login page. No auth required —
/// the same list was previously baked into the server-rendered login HTML.
pub async fn list_public_providers(State(state): State<AppState>) -> Response {
    match state.external_oauth.list().await {
        Ok(providers) => {
            let active: Vec<PublicProvider> = providers
                .into_iter()
                .filter(|provider| provider.status == "active")
                .map(|provider| PublicProvider {
                    slug: provider.slug,
                    name: provider.name,
                })
                .collect();
            (StatusCode::OK, axum::Json(active)).into_response()
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list public external providers");
            error::internal()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExternalCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn start_external_login(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<ExternalLoginQuery>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> Response {
    let provider = match state.external_oauth.find(&slug).await {
        Ok(provider) if provider.status == "active" => provider,
        Ok(_) => return external_error(&state, &slug, "oauth_provider_not_found").await,
        Err(error_value) => {
            tracing::error!(error = %error_value, provider = %slug, "failed to load external OAuth provider");
            return external_error(&state, &slug, "oauth_login_failed").await;
        }
    };
    if let Some(request_id) = query.request_id.as_deref()
        && !pending_request_exists(&state, request_id).await
    {
        return Redirect::to("/login?external_error=oauth_request_expired").into_response();
    }
    let source_ip = match crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    ) {
        Some(source_ip) => Some(source_ip),
        None => match state.config.missing_source_ip_policy {
            MissingSourceIpPolicy::Skip => {
                tracing::warn!(
                    event = "auth_limiter.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Skip.as_str(),
                    "external OAuth state admission is using no source-IP rate dimension"
                );
                None
            }
            MissingSourceIpPolicy::Reject => {
                tracing::error!(
                    event = "auth_limiter.source_ip_unavailable",
                    policy = MissingSourceIpPolicy::Reject.as_str(),
                    "external OAuth login rejected without trusted ConnectInfo"
                );
                return error::internal();
            }
        },
    };
    let state_value = random_state();
    // RFC 9700 §2.1.1：本系统作为 OAuth 客户端访问外部 IdP 时也必须使用 PKCE。
    // verifier 只存在于 Redis 中的 state payload 里，不进入重定向 URL、日志或审计。
    // provider 显式关闭 PKCE 时用空串，authorization_url / exchange_code 会跳过 PKCE 参数。
    let code_verifier = if provider.pkce_enabled {
        generate_code_verifier()
    } else {
        String::new()
    };
    let limits = match state.settings.security_limits().await {
        Ok(limits) => limits,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load external OAuth security limits");
            return error::internal();
        }
    };
    let login_state = ExternalLoginState {
        state: state_value.clone(),
        provider_slug: slug.clone(),
        request_id: query.request_id.clone().filter(|value| !value.is_empty()),
        code_verifier: code_verifier.clone(),
    };
    let save_result = match source_ip.as_deref() {
        Some(source_ip) => {
            state
                .external_login_states
                .save_from_source_with_limits(&login_state, source_ip, &limits)
                .await
        }
        None => {
            state
                .external_login_states
                .save_without_source_with_limits(&login_state, &limits)
                .await
        }
    };
    if let Err(store_error) = save_result {
        if matches!(
            &store_error,
            crate::oauth::providers::state_store::ExternalLoginStateStoreError::RateLimited
                | crate::oauth::providers::state_store::ExternalLoginStateStoreError::CapacityExceeded
        ) {
            tracing::warn!(
                event = "external_oauth.state_admission_denied",
                provider = %slug,
                "external OAuth state admission limit reached"
            );
            if let Err(audit_error) = state
                .audit
                .record(AuditEvent::security_failure(
                    "login_rate_limited".to_owned(),
                    "anonymous".to_owned(),
                    None,
                    "external_oauth".to_owned(),
                    Some(slug.clone()),
                    "state_admission_denied",
                ))
                .await
            {
                tracing::error!(error = %audit_error, "failed to audit external OAuth rate limit");
            }
            return error::too_many_requests(
                "oauth_login_rate_limited",
                "too many external login attempts; try again later",
            );
        }
        tracing::error!(error = %store_error, "failed to store external OAuth state");
        return error::internal();
    }
    let callback_path = external_callback_path(&slug);
    let callback = format!("{}{}", state.config.issuer_url, callback_path);
    let authorization_url = match state.external_oauth.authorization_url(
        &provider,
        &callback,
        &state_value,
        &code_verifier,
    ) {
        Ok(url) => url,
        Err(error_value) => {
            tracing::error!(error = %error_value, provider = %slug, "failed to build external OAuth URL");
            return external_error_with_state(&state, &slug, &state_value, "oauth_login_failed")
                .await;
        }
    };
    let mut response = Redirect::to(&authorization_url).into_response();
    cookies::append_external_state_cookie(
        response.headers_mut(),
        &state_value,
        limits.external_login_state_ttl_seconds,
        state.config.cookie_secure,
        &callback_path,
    );
    response
}

pub async fn external_callback(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Query(query): Query<ExternalCallbackQuery>,
) -> Response {
    let callback_path = external_callback_path(&slug);
    let Some(returned_state) = query.state.as_deref().filter(|value| !value.is_empty()) else {
        return external_error(&state, &slug, "oauth_login_failed").await;
    };
    let cookie_state = cookies::external_state(&headers, returned_state);
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
    let stored_state = match state.external_login_states.take(returned_state).await {
        Ok(Some(value)) if value.provider_slug == slug => value,
        Ok(_) => {
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
    let callback = format!("{}{}", state.config.issuer_url, callback_path);
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
            tracing::info!(error = %error_value, provider = %slug, "external OAuth userinfo failed");
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
    let user_id = match state
        .external_oauth
        .resolve_user(&provider, &external_user)
        .await
    {
        Ok(user_id) => user_id,
        Err(ExternalOAuthError::EmailAlreadyRegistered) => {
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                Some(returned_state),
                "oauth_account_link_required",
            )
            .await;
        }
        Err(ExternalOAuthError::UserDisabled) => {
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                Some(returned_state),
                "oauth_login_failed",
            )
            .await;
        }
        Err(ExternalOAuthError::OwnerBootstrapRequired) => {
            return external_error_with_request(
                &state,
                &slug,
                stored_state.request_id.as_deref(),
                Some(returned_state),
                "owner_bootstrap_required",
            )
            .await;
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, provider = %slug, "failed to resolve external OAuth identity");
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
    let ttl = std::time::Duration::from_secs(state.config.session_ttl_seconds);
    let idle_timeout = std::time::Duration::from_secs(state.config.session_idle_timeout_seconds);
    let mut session = match Session::new_with_idle_timeout(user_id.to_string(), ttl, idle_timeout) {
        Ok(session) => session,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create external OAuth session");
            let mut response = error::internal();
            append_external_state_clear(
                &mut response,
                returned_state,
                &callback_path,
                state.config.cookie_secure,
            );
            return response;
        }
    };
    if let Err(error_value) = state.sessions.save(&mut session, ttl).await {
        tracing::error!(error = %error_value, "failed to save external OAuth session");
        let mut response = error::internal();
        append_external_state_clear(
            &mut response,
            returned_state,
            &callback_path,
            state.config.cookie_secure,
        );
        return response;
    }
    let request_id = stored_state
        .request_id
        .as_deref()
        .filter(|value| !value.is_empty());
    let holder_hash = cookies::extract_authz_holder_cookie(&headers)
        .as_deref()
        .map(cookies::authz_holder_hash);
    if let Some(request_id) = request_id
        && let Err(binding_error) = bind_pending_request(
            &state.authorization_requests,
            request_id,
            &session.token,
            holder_hash.as_deref(),
        )
        .await
    {
        let error_code = match binding_error {
            PendingRequestBindingError::Expired => "oauth_request_expired",
            PendingRequestBindingError::Invalid | PendingRequestBindingError::Storage => {
                "oauth_request_binding_failed"
            }
        };
        return external_error_with_session(
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
        .record(AuditEvent::new(
            "user".to_owned(),
            Some(user_id.to_string()),
            "login".to_owned(),
            "session".to_owned(),
            Some(session.id.to_string()),
            serde_json::json!({"result": "success", "channel": "external_oauth", "provider": slug}),
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
        append_external_state_clear(
            &mut response,
            returned_state,
            &callback_path,
            state.config.cookie_secure,
        );
        return response;
    }
    // Session is bound to the pending request above before handing control to the
    // SPA consent screen; otherwise land on the SPA login page.
    let mut response = if let Some(request_id) = request_id {
        Redirect::to(&format!("/oauth/consent?request_id={request_id}")).into_response()
    } else {
        Redirect::to("/login?external=success").into_response()
    };
    cookies::append_login_cookies(
        response.headers_mut(),
        &session.token,
        &session.csrf_token,
        state.config.session_ttl_seconds,
        state.config.cookie_secure,
    );
    append_external_state_clear(
        &mut response,
        returned_state,
        &callback_path,
        state.config.cookie_secure,
    );
    response
}

fn random_state() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
