//! Refresh Token 授权类型的处理逻辑（RFC 9700 §4.14.2）。
//!
//! 从 `token_handlers.rs` 拆出以满足 src-line-limit 500 行强警告。

use axum::{http::StatusCode, response::Response};

use super::{
    refresh_store::Tombstone, response::issue_token_response, session::active_user_id,
    token_handlers::TokenRequest, token_security::record_token_event,
};
use crate::{error, state::AppState};

/// 处理 `grant_type=refresh_token` 的请求。
///
/// 调用前提：客户端凭据已在 `token_inner` 中校验完毕，
/// `request.client_id` 已被规范化为经过认证的 `client_id`。
pub async fn exchange_refresh_token(state: AppState, request: TokenRequest) -> Response {
    let Some(refresh_value) = request.refresh_token.as_deref() else {
        return error::oauth_bad_request("invalid_request", "refresh_token is required");
    };
    let Some(client_id) = request.client_id.as_deref() else {
        return error::oauth_invalid_client();
    };
    let refresh = match state.refresh_tokens.find(refresh_value).await {
        Ok(Some(refresh)) => refresh,
        Ok(None) => {
            // Token 不存在：可能从未签发，也可能已被正常轮换（重放）。
            // 读取墓碑区分两种情况（RFC 9700 §4.14.2）。
            return handle_missing_refresh_token(&state, client_id, refresh_value).await;
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve refresh token");
            return error::oauth_temporarily_unavailable();
        }
    };
    if refresh
        .validate(client_id, time::OffsetDateTime::now_utc())
        .is_err()
    {
        if record_token_event(
            &state,
            Some(&refresh.user_id),
            "token_refresh_failure",
            Some(client_id),
            "invalid_token",
        )
        .await
        .is_err()
        {
            return error::oauth_server_error();
        }
        return error::oauth_bad_request("invalid_grant", "refresh token is invalid");
    }
    match state
        .revocations
        .is_consent_revoked(&refresh.user_id, client_id)
        .await
    {
        Ok(true) => {
            return error::oauth_bad_request("invalid_grant", "refresh token is invalid");
        }
        Ok(false) => {}
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to check OAuth consent revocation");
            return error::oauth_temporarily_unavailable();
        }
    }
    let Ok(user_id) = refresh.user_id.parse::<crate::users::domain::UserId>() else {
        return error::oauth_bad_request("invalid_grant", "refresh token is invalid");
    };
    match state
        .consents
        .has_scopes(user_id, client_id, &refresh.scopes)
        .await
    {
        Ok(true) => {}
        Ok(false) => return error::oauth_bad_request("invalid_grant", "refresh token is invalid"),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to check refresh token consent");
            return error::oauth_temporarily_unavailable();
        }
    }
    match active_user_id(&state, &refresh.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return error::oauth_bad_request("invalid_grant", "refresh token is invalid"),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load refresh token user");
            return error::oauth_temporarily_unavailable();
        }
    }
    let scopes = match request.scope.as_deref() {
        Some(scope) => {
            let requested = scope
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if requested
                .iter()
                .any(|scope| !refresh.scopes.contains(scope))
            {
                return error::oauth_bad_request(
                    "invalid_scope",
                    "requested scope exceeds original grant",
                );
            }
            requested
        }
        None => refresh.scopes.clone(),
    };
    // `rotate()` 继承 `issued_at` 和 `family_id`（Issue #109 / #110 的关键修复）。
    // 旧实现用 `RefreshToken::new()` 每次产生全新的 created_at，绝对生命周期永远不计时。
    let next_refresh = refresh.rotate(scopes.clone());
    let response = issue_token_response(
        &state,
        &refresh.user_id,
        client_id,
        &scopes,
        Some(next_refresh.value.clone()),
        None,
        // 刷新流程没有会话上下文，`auth_time` 未知就省略，不填错的值。
        None,
    )
    .await;
    if response.status() != StatusCode::OK {
        return response;
    }
    match state
        .refresh_tokens
        .rotate_if_matches(refresh_value, &refresh, &next_refresh)
        .await
    {
        Ok(true) => {
            if record_token_event(
                &state,
                Some(&refresh.user_id),
                "token_refresh",
                Some(client_id),
                "success",
            )
            .await
            .is_err()
            {
                if let Err(error_value) = state.refresh_tokens.remove(&next_refresh.value).await {
                    tracing::warn!(
                        error = %error_value,
                        "failed to compensate refresh token after audit persistence failure"
                    );
                }
                if let Err(error_value) = state.refresh_tokens.save(&refresh).await {
                    tracing::warn!(
                        error = %error_value,
                        "failed to restore previous refresh token after audit persistence failure"
                    );
                }
                return error::oauth_server_error();
            }
            response
        }
        Ok(false) => {
            // CAS 竞争失败：另一个并发请求赢得了轮换，说明同一个 refresh token
            // 被并发提交了两次。这是凭据泄露的强信号（RFC 9700 §4.14.2）——
            // 攻击者与合法客户端各持一份，只拒绝当次请求会让攻击者继续轮换下去，
            // 因此必须撤销整个 family。
            let tombstone = match state.refresh_tokens.read_tombstone(refresh_value).await {
                Ok(tombstone) => tombstone,
                Err(store_error) => {
                    tracing::error!(error = %store_error, "failed to read refresh token tombstone");
                    return error::oauth_temporarily_unavailable();
                }
            };
            match tombstone {
                // 墓碑由胜出方写入。此处 client 绑定已在前面 `validate` 校验过，
                // 仍显式比较，避免将来改动意外引入跨 client 撤销。
                Some(tombstone) if tombstone.client_id == client_id => {
                    revoke_family_after_replay(&state, client_id, &tombstone).await
                }
                _ => {
                    // 墓碑缺失（极小概率竞态）：定位不到 family，只能拒绝当次请求。
                    tracing::warn!(
                        client_id = %client_id,
                        "refresh rotation lost CAS race but tombstone is missing; \
                         cannot revoke family"
                    );
                    record_and_return_invalid(
                        &state,
                        Some(&refresh.user_id),
                        client_id,
                        "token_race",
                    )
                    .await
                }
            }
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to atomically rotate refresh token");
            error::oauth_temporarily_unavailable()
        }
    }
}

/// 处理 `find` 返回 `None`：读取墓碑区分「从未签发」与「已被消费后重放」。
///
/// 墓碑存在且 `client_id` 匹配 → 确认重放，撤销整个 family（RFC 9700 §4.14.2）。
///
/// 墓碑存在但 `client_id` 不匹配 → 静默拒绝，**不撤销任何东西**。
/// 这是防跨 client DoS 的关键（Issue #110 设计决策 §3）：如果不校验，
/// Client A 只要提交一个 Client B 的旧 token，就能摧毁 B 的整个 family，
/// 重放防御会变成攻击 B 的原语。
async fn handle_missing_refresh_token(
    state: &AppState,
    client_id: &str,
    refresh_value: &str,
) -> Response {
    match state.refresh_tokens.read_tombstone(refresh_value).await {
        Ok(Some(tombstone)) if tombstone.client_id == client_id => {
            revoke_family_after_replay(state, client_id, &tombstone).await
        }
        Ok(Some(_)) => {
            // 不记录提交的 token 值，它是凭据。
            tracing::warn!(
                client_id = %client_id,
                "refresh token replay attempt with mismatched client_id; \
                 refusing without revoking the owning family"
            );
            record_and_return_invalid(state, None, client_id, "invalid_token").await
        }
        // 墓碑不存在 → 普通无效 token（从未签发，或墓碑已过 30 天窗口）
        Ok(None) => record_and_return_invalid(state, None, client_id, "invalid_token").await,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to read refresh token tombstone");
            error::oauth_temporarily_unavailable()
        }
    }
}

/// 确认重放后撤销整个 family，写审计并返回 `invalid_grant`（RFC 9700 §4.14.2）。
///
/// 调用方必须已确认 `tombstone.client_id` 与请求的 client 一致。
///
/// 撤销失败不改变对外结果：请求无论如何都要被拒绝，
/// 失败只通过 `tracing::error!` 暴露给运维，不让 500 掩盖掉「凭据已泄露」的信号。
async fn revoke_family_after_replay(
    state: &AppState,
    client_id: &str,
    tombstone: &Tombstone,
) -> Response {
    match state
        .refresh_tokens
        .revoke_family(&tombstone.family_id, client_id, &tombstone.user_id)
        .await
    {
        Ok(revoked) => {
            tracing::warn!(
                client_id = %client_id,
                family_id = %tombstone.family_id,
                revoked_refresh_tokens = revoked,
                "refresh token replay detected; revoked entire token family"
            );
        }
        Err(store_error) => {
            tracing::error!(
                error = %store_error,
                client_id = %client_id,
                family_id = %tombstone.family_id,
                "failed to revoke refresh token family after replay detection"
            );
        }
    }
    record_and_return_invalid(
        state,
        Some(&tombstone.user_id),
        client_id,
        "refresh_replay_detected",
    )
    .await
}

/// 写 token_refresh_failure 审计事件并返回 `invalid_grant`。
async fn record_and_return_invalid(
    state: &AppState,
    user_id: Option<&str>,
    client_id: &str,
    reason: &str,
) -> Response {
    if record_token_event(
        state,
        user_id,
        "token_refresh_failure",
        Some(client_id),
        reason,
    )
    .await
    .is_err()
    {
        return error::oauth_server_error();
    }
    error::oauth_bad_request("invalid_grant", "refresh token is invalid")
}
