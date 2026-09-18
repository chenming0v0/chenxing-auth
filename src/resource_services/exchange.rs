//! 一键登录兑换端点（Issue #709）。
//!
//! `POST /api/v1/auth/chenxing/exchange` 接收浏览器持有的辰星 Access Token，
//! 校验它确实是本 Issuer 为某个 OAuth Client 签发、且授权（grant gate）此刻仍然
//! 覆盖某个已启用资源服务声明的 scope，再为「该资源服务上已绑定的账号」签发
//! 一枚 300 秒的 RS256 会话令牌。
//!
//! 本端点由用户浏览器直接调用，没有入站 interop 凭据，认证材料只有用户自己的
//! Access Token。校验顺序按成本递增、尽早拒绝，并在签发前做一次按 subject 的
//! 滑动窗口限流。`device_id` / `device_info` 只进审计，不作为设备判定依据，也
//! 永远不落库。
//!
//! 资源服务的选择：令牌 scope 与已启用服务的 scope 取交集；多个候选时请求体
//! 必须用 `provider`（slug）指明；`restricted` 服务还要求令牌的 `aud` 在其
//! `allowed_client_ids` 内。

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use time::OffsetDateTime;

use crate::{
    api::extract::{ApiJson, RequestIssuer},
    audit::AuditEvent,
    error,
    oauth::{
        grant_gate::{GrantGateError, effective_grant_scopes},
        response::with_no_store_headers,
        token::{TokenError, decode_userinfo_token, issue_session_token_at},
    },
    state::AppState,
    users::domain::{UserId, UserStatus},
};

use super::types::ScopeAccess;

mod support;

pub use support::ExchangeInput;
use support::{
    BAD_REQUEST_MESSAGE, EXCHANGE_RATE_LIMIT, EXCHANGE_RATE_WINDOW_MS, INVALID_TOKEN_MESSAGE,
    MAX_DEVICE_ID_BYTES, MAX_DEVICE_INFO_BYTES, NOT_LINKED_MESSAGE, SESSION_TOKEN_LIFETIME_SECONDS,
    Selection, UNAVAILABLE_MESSAGE, bearer_token, select_provider, snapshot_status,
};

#[derive(Serialize)]
struct ExchangeResponse {
    session_token: String,
    uid: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

pub async fn exchange(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ExchangeInput>,
) -> Response {
    if input.device_id.is_empty() || input.device_id.len() > MAX_DEVICE_ID_BYTES {
        return error::bad_request("invalid_request", BAD_REQUEST_MESSAGE);
    }
    if input
        .device_info
        .as_deref()
        .is_some_and(|value| value.len() > MAX_DEVICE_INFO_BYTES)
    {
        return error::bad_request("invalid_request", BAD_REQUEST_MESSAGE);
    }
    let requested_slug = input
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let Some(token) = bearer_token(&headers) else {
        return denied(&state, None, None).await;
    };
    let claims = match decode_userinfo_token(&state.keys, issuer.issuer().as_str(), token) {
        Ok(claims) => claims,
        Err(_) => return denied(&state, None, None).await,
    };
    let sub = claims.sub.as_str();
    // 撤销检查 fail-closed：Redis 故障时无法证明令牌未被撤销，不能签出新的会话令牌。
    match state.revocations.is_revoked(token).await {
        Ok(false) => {}
        Ok(true) | Err(_) => return denied(&state, Some(sub), None).await,
    }

    let presented = claims
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let scopes = match effective_grant_scopes(&state, sub, &claims.aud, &presented).await {
        Ok(grant) => grant.scopes,
        Err(GrantGateError::Denied(_)) => return denied(&state, Some(sub), None).await,
        Err(GrantGateError::Unavailable(_)) => return unavailable(&state, Some(sub), None).await,
    };

    let providers = match state.resource_services.provider_scopes().await {
        Ok(providers) => providers,
        Err(_) => return unavailable(&state, Some(sub), None).await,
    };
    let provider = match select_provider(providers, &scopes, requested_slug) {
        Selection::Chosen(provider) => provider,
        Selection::NoScope => {
            record_denied(&state, Some(sub), "insufficient_scope", requested_slug).await;
            return error::forbidden(
                "insufficient_scope",
                "the access token lacks a resource service scope",
            );
        }
        Selection::Ambiguous => {
            record_denied(&state, Some(sub), "invalid_request", None).await;
            return error::bad_request(
                "invalid_request",
                "multiple resource services match; specify `provider`",
            );
        }
    };
    let slug = provider.slug.as_str();
    if provider.access == ScopeAccess::Restricted
        && !provider
            .allowed_client_ids
            .iter()
            .any(|id| id == &claims.aud)
    {
        return denied(&state, Some(sub), Some(slug)).await;
    }

    let Ok(user_id) = sub.parse::<UserId>() else {
        return denied(&state, Some(sub), Some(slug)).await;
    };
    match state.users.find_profile(user_id).await {
        Ok(Some(profile)) if UserStatus::parse(&profile.status) == Some(UserStatus::Active) => {}
        Ok(Some(_)) | Ok(None) => return denied(&state, Some(sub), Some(slug)).await,
        Err(_) => return unavailable(&state, Some(sub), Some(slug)).await,
    }

    // 限流放在签发之前：它保护的是「会话令牌签发」这个动作本身，必须在任何
    // 令牌被签出之前生效。
    match state
        .qps
        .allow_scoped(
            &format!("chenxing:resource-service-exchange:{sub}"),
            EXCHANGE_RATE_LIMIT,
            EXCHANGE_RATE_WINDOW_MS,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            record_denied(&state, Some(sub), "rate_limited", Some(slug)).await;
            return error::too_many_requests(
                "rate_limited",
                "the exchange request is rate limited",
            );
        }
        Err(_) => return unavailable(&state, Some(sub), Some(slug)).await,
    }

    let binding = match state
        .resource_services
        .live_binding(provider.provider_id, user_id)
        .await
    {
        Ok(Some(binding)) => binding,
        Ok(None) => {
            record_denied(&state, Some(sub), "account_not_linked", Some(slug)).await;
            return error::forbidden("account_not_linked", NOT_LINKED_MESSAGE);
        }
        Err(_) => return unavailable(&state, Some(sub), Some(slug)).await,
    };
    match snapshot_status(&binding) {
        Some("active") => {}
        Some("disabled") => {
            record_denied(&state, Some(sub), "account_disabled", Some(slug)).await;
            return error::forbidden("account_disabled", "the linked account is disabled");
        }
        _ => {
            record_denied(&state, Some(sub), "account_not_linked", Some(slug)).await;
            return error::forbidden("account_not_linked", NOT_LINKED_MESSAGE);
        }
    }
    let Ok(binding_version) = i32::try_from(binding.generation) else {
        return unavailable(&state, Some(sub), Some(slug)).await;
    };

    let now = state.clock.now();
    let binding_id = binding.id.to_string();
    let session_token = match issue_session_token_at(
        &state.keys,
        issuer.issuer().as_str(),
        sub,
        &claims.aud,
        &scopes,
        SESSION_TOKEN_LIFETIME_SECONDS,
        now,
        &binding.uid,
        &binding_id,
        binding_version,
    ) {
        Ok(token) => token,
        Err(token_error) => {
            // 只记录安全的原因分类，绝不输出签名错误细节或令牌材料。
            match &token_error {
                TokenError::SigningUnavailable => {
                    tracing::error!("resource service session token signing is unavailable");
                }
                _ => tracing::error!("failed to sign resource service session token"),
            }
            return unavailable(&state, Some(sub), Some(slug)).await;
        }
    };
    let expires_at = now + time::Duration::seconds(SESSION_TOKEN_LIFETIME_SECONDS as i64);
    state
        .audit
        .record_best_effort(AuditEvent::new(
            "user".to_owned(),
            Some(claims.sub.clone()),
            crate::audit::AuditAction::ResourceServiceExchange,
            "resource_service_binding".to_owned(),
            Some(binding_id.clone()),
            serde_json::json!({
                "provider": slug,
                "uid": &binding.uid,
                "binding_id": binding_id,
                "device_id": &input.device_id,
                "result": "success",
            }),
        ))
        .await;

    with_no_store_headers(
        (
            StatusCode::OK,
            Json(ExchangeResponse {
                session_token,
                uid: binding.uid,
                expires_at,
            }),
        )
            .into_response(),
    )
}

/// 统一的 Chenxing 令牌无效回应：先留痕再返回 401。
async fn denied(state: &AppState, actor_id: Option<&str>, provider: Option<&str>) -> Response {
    record_denied(state, actor_id, "invalid_chenxing_token", provider).await;
    error::unauthorized("invalid_chenxing_token", INVALID_TOKEN_MESSAGE)
}

/// 统一的存储/限流基础设施不可用回应：先留痕再返回 503。
async fn unavailable(state: &AppState, actor_id: Option<&str>, provider: Option<&str>) -> Response {
    record_denied(state, actor_id, "provider_unavailable", provider).await;
    error::service_unavailable("provider_unavailable", UNAVAILABLE_MESSAGE)
}

/// 记录一次兑换拒绝/失败。只记录稳定的 `code` 与资源服务 slug；`device_id`
/// 与 `device_info` 不进入失败事件的元数据，任何令牌材料都不记录。
async fn record_denied(
    state: &AppState,
    actor_id: Option<&str>,
    code: &str,
    provider: Option<&str>,
) {
    state
        .audit
        .record_best_effort(AuditEvent::new(
            "user".to_owned(),
            actor_id.map(str::to_owned),
            crate::audit::AuditAction::ResourceServiceExchangeDenied,
            "resource_service_binding".to_owned(),
            None,
            serde_json::json!({ "code": code, "provider": provider }),
        ))
        .await;
}
