//! OAuth AT → v2 product/device-bound login ticket. Go owns all device slots.
//! Provider selection, live grants and AP linkage remain authoritative; this
//! endpoint only issues a 300-second assertion, never a business session.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use time::OffsetDateTime;

use crate::{
    api::extract::RequestIssuer,
    audit::AuditEvent,
    error,
    oauth::{
        grant_gate::{GrantGateError, effective_grant_scopes},
        response::with_no_store_headers,
        token::{TokenError, decode_userinfo_token},
    },
    state::AppState,
    users::domain::{UserId, UserStatus},
};

use super::types::ScopeAccess;

mod http;
mod support;
mod ticket;

use http::ExchangeJson;
pub use http::{response_boundary, retired};
use support::{
    BAD_REQUEST_MESSAGE, EXCHANGE_RATE_LIMIT, EXCHANGE_RATE_WINDOW_MS, INVALID_TOKEN_MESSAGE,
    NOT_LINKED_MESSAGE, Selection, UNAVAILABLE_MESSAGE, bearer_token, select_provider,
    snapshot_status,
};
use ticket::{AppKind, LIFETIME_SECONDS, LOGIN_SCOPE};

#[derive(Serialize)]
struct ExchangeResponse {
    v: u8,
    login_ticket: String,
    uid: String,
    app_kind: AppKind,
    device_id: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

pub async fn exchange(
    State(state): State<AppState>,
    issuer: RequestIssuer,
    headers: HeaderMap,
    ExchangeJson(input): ExchangeJson,
) -> Response {
    if !input.is_valid() {
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
        Ok(true) => return denied(&state, Some(sub), None).await,
        Err(_) => return unavailable(&state, Some(sub), None).await,
    }

    // Reuse the OAuth client store, whose package declaration is Owner-managed.
    let client = match state.clients.find_registered(&claims.aud).await {
        Ok(client) => client,
        Err(_) => return unavailable(&state, Some(sub), None).await,
    };
    let app = client
        .and_then(|client| client.android_package)
        .as_deref()
        .and_then(AppKind::from_package);
    if app != Some(input.app_kind) {
        record_denied(&state, Some(sub), "app_not_allowed", None).await;
        return error::forbidden(
            "app_not_allowed",
            "the OAuth client is not allowed for this app",
        );
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
    if provider.scope != LOGIN_SCOPE {
        record_denied(&state, Some(sub), "insufficient_scope", Some(slug)).await;
        return error::forbidden(
            "insufficient_scope",
            "the access token lacks cltermux:access",
        );
    }
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
        Ok(Some(_)) => {
            record_denied(&state, Some(sub), "account_disabled", Some(slug)).await;
            return error::forbidden("account_disabled", "the account is disabled");
        }
        Ok(None) => return denied(&state, Some(sub), Some(slug)).await,
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
    if !ticket::valid_uid(&binding.uid) {
        record_denied(&state, Some(sub), "account_not_linked", Some(slug)).await;
        return error::forbidden("account_not_linked", NOT_LINKED_MESSAGE);
    }
    if binding.generation <= 0 {
        return unavailable(&state, Some(sub), Some(slug)).await;
    }

    let now = state.clock.now();
    let now = now - time::Duration::nanoseconds(i64::from(now.nanosecond()));
    let binding_id = binding.id.to_string();
    let login_ticket = match ticket::issue(&state.keys, &claims, &binding, &input, now) {
        Ok(token) => token,
        Err(token_error) => {
            // 只记录安全的原因分类，绝不输出签名错误细节或令牌材料。
            match &token_error {
                TokenError::SigningUnavailable => {
                    tracing::error!("login ticket signing is unavailable");
                }
                _ => tracing::error!("failed to sign login ticket"),
            }
            return unavailable(&state, Some(sub), Some(slug)).await;
        }
    };
    let expires_at = now + time::Duration::seconds(LIFETIME_SECONDS);
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
                "app_kind": input.app_kind,
                "result": "success",
            }),
        ))
        .await;

    with_no_store_headers(
        (
            StatusCode::OK,
            Json(ExchangeResponse {
                v: 2,
                login_ticket,
                uid: binding.uid,
                app_kind: input.app_kind,
                device_id: input.device_id,
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
