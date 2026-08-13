use axum::{
    extract::{ConnectInfo, Extension, RawForm, State, rejection::RawFormRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::{fmt, net::SocketAddr};

use super::{
    client_auth::resolve_client_credentials, form, refresh::RefreshToken,
    response::with_no_store_headers, token::decode_access_token,
    token_security::enforce_source_qps_with_policy,
};
use crate::{audit::AuditEvent, error, state::AppState};

#[derive(Deserialize)]
pub struct RevocationRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl fmt::Debug for RevocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationRequest")
            .field("token", &"<redacted>")
            .field("token_type_hint", &self.token_type_hint)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    form: Result<RawForm, RawFormRejection>,
) -> Response {
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    if let Some(response) = enforce_source_qps_with_policy(&state, source_ip.as_deref()).await {
        return with_no_store_headers(response);
    }

    let RawForm(body) = match form {
        Ok(form) => form,
        Err(_) => {
            return with_no_store_headers(error::oauth_bad_request(
                "invalid_request",
                "request body is invalid",
            ));
        }
    };
    let request = match form::deserialize(&body) {
        Some(request) => request,
        None => {
            return with_no_store_headers(error::oauth_bad_request(
                "invalid_request",
                "request body is invalid",
            ));
        }
    };
    with_no_store_headers(revoke_inner(state, headers, request).await)
}

async fn revoke_inner(state: AppState, headers: HeaderMap, request: RevocationRequest) -> Response {
    let credentials = match resolve_client_credentials(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    ) {
        Ok(credentials) => credentials,
        // 缺失、格式错误、超长或方式混用都是客户端认证失败，统一 invalid_client
        // （Issue #353：超长凭据必须在解析层被拒，不能流入 Argon2 / DB 绑定）。
        Err(_) => {
            return error::oauth_invalid_client();
        }
    };
    match state
        .clients
        .verify_credentials(
            &credentials.client_id,
            credentials.auth_method,
            credentials.client_secret.as_deref(),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return error::oauth_invalid_client();
        }
        Err(client_error) => {
            tracing::error!(error = %client_error, "failed to verify revocation client credentials");
            return error::oauth_temporarily_unavailable();
        }
    }
    if request.token.is_empty() {
        return error::oauth_bad_request("invalid_request", "token is required");
    }

    if !matches!(
        request.token_type_hint.as_deref(),
        None | Some("access_token") | Some("refresh_token")
    ) {
        return error::oauth_bad_request(
            "unsupported_token_type",
            "token type hint is unsupported",
        );
    }

    let hint = request.token_type_hint.as_deref();
    // RFC 7009 treats the hint as a lookup preference, not an exclusive type filter.
    let refresh_first = !matches!(hint, Some("access_token"));
    if refresh_first {
        match try_revoke_refresh_token(&state, &request.token, &credentials.client_id).await {
            Ok(true) => return ().into_response(),
            Ok(false) => {}
            Err(response) => return response,
        }
    }

    let access_token_found = if let Ok(claims) = decode_access_token(
        &state.keys,
        &state.config.issuer_url,
        &credentials.client_id,
        &request.token,
    ) {
        let now = state.clock.now().unix_timestamp();
        if let Ok(expires_at) = i64::try_from(claims.exp) {
            let ttl = expires_at.saturating_sub(now);
            if ttl > 0
                && let Err(store_error) = state.revocations.revoke(&request.token, ttl as u64).await
            {
                tracing::error!(error = %store_error, "failed to revoke access token");
                return error::oauth_temporarily_unavailable();
            }
            // 审计失败同样不撤回撤销标记：删掉它等于让一个客户端已经作废的
            // access token 在剩余 TTL 内重新可用。返回 500 并留下可检索日志。
            if ttl > 0
                && record_revocation_event(
                    &state,
                    Some(&claims.sub),
                    &credentials.client_id,
                    "access_token",
                    serde_json::json!({}),
                )
                .await
                .is_err()
            {
                tracing::error!(
                    event = "audit.token_revoke_unrecorded",
                    client_id = %credentials.client_id,
                    "access token was revoked but the audit event could not be persisted; \
                     keeping the revocation"
                );
                return error::oauth_server_error();
            }
        }
        true
    } else {
        false
    };

    if !refresh_first && !access_token_found {
        match try_revoke_refresh_token(&state, &request.token, &credentials.client_id).await {
            Ok(true) => return ().into_response(),
            Ok(false) => {}
            Err(response) => return response,
        }
    }

    ().into_response()
}

/// 撤销一个 Refresh Token 所属的整个 grant family（Issue #295）。
///
/// RFC 7009 说的是「撤销 token」，但轮换让一个 grant 在时间上表现为一串 token。
/// 只删提交的那一个会留下两个洞：
///
/// 1. 轮换后仍然存活的后继 token 不受影响，客户端以为 grant 已经撤销，实际上
///    攻击者手里那个轮换后的值还能继续兑换。
/// 2. 撤销请求与一次飞行中的轮换竞争时，撤销可能正好落在刚被消费的旧 token
///    上，新 token 安然无恙——撤销变成了空操作。
///
/// 因此这里的撤销单元是 family，并且即使提交的 token 已经不在（被并发轮换
/// 消费掉），只要墓碑证明它属于本 Client，就照样把它的 family 排空。
/// family 撤销墓志会同时挡住任何还在飞行中的轮换写回新成员。
async fn try_revoke_refresh_token(
    state: &AppState,
    token: &str,
    client_id: &str,
) -> Result<bool, Response> {
    let grant = match resolve_revocable_grant(state, token, client_id).await? {
        Some(grant) => grant,
        None => return Ok(false),
    };
    let revocation = match state
        .refresh_tokens
        .revoke_family_on_explicit_revoke(&grant.family_id, client_id, &grant.user_id, token)
        .await
    {
        Ok(revocation) => revocation,
        Err(store_error) => {
            tracing::error!(
                event = "refresh.explicit_revocation_failed",
                error = %store_error,
                client_id = %client_id,
                family_id = %grant.family_id,
                "failed to revoke the refresh token grant family"
            );
            return Err(error::oauth_temporarily_unavailable());
        }
    };
    // 审计失败不复活凭据。撤销已经不可逆地完成，`save` 回去只会让一个客户端
    // 明确要求作废的 grant 重新可兑换。返回 500 让调用方知道这次撤销没有留下
    // 完整记录；重试是幂等的（family 墓志已经在，只会再试一次审计写入）。
    if record_revocation_event(
        state,
        Some(&grant.user_id),
        client_id,
        "refresh_token",
        serde_json::json!({
            "family_id": grant.family_id,
            "revoked_refresh_tokens": revocation.revoked_tokens,
            "already_revoked": revocation.already_revoked,
        }),
    )
    .await
    .is_err()
    {
        tracing::error!(
            event = "audit.token_revoke_unrecorded",
            client_id = %client_id,
            family_id = %grant.family_id,
            "refresh token grant was revoked but the audit event could not be persisted; \
             keeping the revocation"
        );
        return Err(error::oauth_server_error());
    }

    Ok(true)
}

/// 提交的 token 所属 grant 的定位结果（都取自服务端状态，不取自请求参数）。
struct RevocableGrant {
    family_id: String,
    user_id: String,
}

/// 定位提交 token 所属的 grant，并确认它归属发起撤销的 Client。
///
/// 活 token 走 payload；已经被消费掉的 token 走墓碑——否则一次「轮换刚完成、
/// 客户端拿旧值来撤销」的正常请求会被当成未知 token 静默放过，而那个 grant
/// 的新成员仍然活着。
async fn resolve_revocable_grant(
    state: &AppState,
    token: &str,
    client_id: &str,
) -> Result<Option<RevocableGrant>, Response> {
    match state.refresh_tokens.find(token).await {
        Ok(Some(refresh)) if refresh.client_id == client_id => {
            return Ok(Some(RevocableGrant {
                // 旧格式 token 的 payload 里 family 是空串：用 token 值派生
                // 家族标识，与轮换后继所在家族一致，撤销才不是空操作
                // （Issue #313）。
                family_id: refresh.family_identifier(),
                user_id: refresh.user_id,
            }));
        }
        // 别人的 token：按 RFC 7009 静默视为「不是我的 refresh token」。
        Ok(Some(_)) => return Ok(None),
        Ok(None) => {}
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to look up refresh token");
            return Err(error::oauth_temporarily_unavailable());
        }
    }
    match state.refresh_tokens.read_tombstone(token).await {
        Ok(Some(tombstone)) if tombstone.client_id == client_id => Ok(Some(RevocableGrant {
            // 升级前写入的旧墓碑可能没有 family_id（旧格式轮换不记录后继
            // 家族）：由提交值哈希派生，命中轮换后继所在的同一撤销域
            // （Issue #313）。
            family_id: RefreshToken::resolve_family_identifier(&tombstone.family_id, token),
            user_id: tombstone.user_id,
        })),
        Ok(_) => Ok(None),
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to read refresh token tombstone");
            Err(error::oauth_temporarily_unavailable())
        }
    }
}

async fn record_revocation_event(
    state: &AppState,
    actor_id: Option<&str>,
    client_id: &str,
    token_type: &str,
    mut metadata: serde_json::Value,
) -> Result<(), crate::audit::AuditError> {
    if let Some(object) = metadata.as_object_mut() {
        object.insert("token_type".to_owned(), token_type.into());
        object.insert("result".to_owned(), "success".into());
    }
    state
        .audit
        .record_blocking(AuditEvent::new(
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "oauth_client".to_owned()
            },
            actor_id.map(str::to_owned),
            "token_revoke".to_owned(),
            "oauth_token".to_owned(),
            Some(client_id.to_owned()),
            metadata,
        ))
        .await
}
