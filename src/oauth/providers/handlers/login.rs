use crate::{
    audit::AuditEvent,
    auth_limiter::MissingSourceIpPolicy,
    error,
    oauth::consent::pending_request_exists,
    oauth::providers::{
        client_pkce::generate_code_verifier,
        domain::is_valid_provider_slug,
        error_helpers::{external_callback_path, external_error, external_error_with_state},
        state_store::ExternalLoginState,
    },
    sessions::cookies,
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use std::{fmt, net::SocketAddr};

#[derive(Deserialize)]
pub struct ExternalLoginQuery {
    pub request_id: Option<String>,
}

impl fmt::Debug for ExternalLoginQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalLoginQuery")
            .field(
                "request_id",
                &self.request_id.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

pub async fn start_external_login(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<ExternalLoginQuery>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> Response {
    // 与回调路由共用同一 slug 校验：非法路径参数不进 DB 查询，也不进审计与日志。
    // 原始 slug 可能携带百分号解码出的控制字符，直接回显会变成日志注入
    // （Issue #344），因此日志只记事件不记原值。
    if !is_valid_provider_slug(&slug) {
        tracing::info!("rejected external OAuth login with an invalid provider slug");
        return error::not_found(
            "oauth_provider_not_found",
            "external OAuth provider not found",
        );
    }
    let provider = match state.external_oauth.find(&slug).await {
        Ok(provider) if provider.status == "active" => provider,
        Ok(_) => return external_error(&state, &slug, "oauth_provider_not_found").await,
        Err(error_value) => {
            tracing::error!(error = %error_value, provider = %slug, "failed to load external OAuth provider");
            return external_error(&state, &slug, "oauth_login_failed").await;
        }
    };
    // Fail-closed（Issue #261）：缺少 email_verified claim 的存量 provider 不可用。
    // 在跳转外部 IdP 之前就拒绝，用户不会走完一整圈才在回调里失败。
    if let Err(mapping_error) = provider.claim_mapping() {
        tracing::error!(
            error = %mapping_error,
            provider = %slug,
            "external OAuth provider is missing a usable email_verified claim"
        );
        return external_error(&state, &slug, "oauth_provider_not_found").await;
    }
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
            state
                .audit
                .record_best_effort(AuditEvent::security_failure(
                    "login_rate_limited".to_owned(),
                    "anonymous".to_owned(),
                    None,
                    "external_oauth".to_owned(),
                    Some(slug.clone()),
                    "state_admission_denied",
                ))
                .await;
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
    if let Err(cookie_error) = cookies::append_external_state_cookie(
        response.headers_mut(),
        &state_value,
        limits.external_login_state_ttl_seconds,
        state.config.cookie_secure,
        &callback_path,
    ) {
        tracing::error!(
            error = %cookie_error,
            provider = %slug,
            "failed to build external OAuth state cookie response"
        );
        return error::internal();
    }
    response
}

fn random_state() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
