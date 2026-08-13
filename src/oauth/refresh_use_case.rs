use super::{OAuthError, RefreshExchangeError, TokenRequest, TokenResponse, issue_token_response};
use crate::{clients::service::AuthenticatedClient, state::AppState, users::domain::UserId};

use super::super::{
    refresh::RefreshToken,
    refresh_store::RotationOutcome,
    session::active_user_epoch,
    token_security::{record_token_event, record_token_event_best_effort},
};

// 重放处置（墓碑分类与 family 撤销）拆在独立文件：安全语义说明密度较高，
// 混在主用例里会让本文件越过源文件长度门槛。
#[path = "refresh_use_case_replay.rs"]
mod replay;
use replay::{ReplayContext, TombstoneDisposition, classify_tombstone, revoke_family_after_replay};

/// Exchange a refresh token after the token endpoint has authenticated the client.
pub(super) async fn exchange_refresh_token(
    state: &AppState,
    request: TokenRequest,
    authenticated: AuthenticatedClient,
) -> Result<TokenResponse, RefreshExchangeError> {
    let Some(refresh_value) = request.refresh_token.as_deref() else {
        return Err(OAuthError::bad_request("invalid_request", "refresh_token is required").into());
    };
    let Some(client_id) = request.client_id.as_deref() else {
        return Err(OAuthError::InvalidClient.into());
    };
    if authenticated.client_id() != client_id {
        return Err(OAuthError::InvalidClient.into());
    }
    let refresh = match state.refresh_tokens.find(refresh_value).await {
        Ok(Some(refresh)) => refresh,
        Ok(None) => {
            // A missing token may be either unknown or a replay of a consumed token.
            return handle_missing_refresh_token(state, client_id, refresh_value).await;
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve refresh token");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    };

    // A Refresh Token is part of the credential generation that created it.
    // Versioned tokens must match the exact authenticated generation. Legacy
    // tokens remain compatible for one exchange and their successor is stamped
    // below; updated issuers never create another unversioned token.
    if !refresh.is_bound_to_client_secret_version(
        authenticated.client_secret_version(),
        authenticated.allows_legacy_refresh_tokens(),
    ) {
        return record_and_return_invalid(
            state,
            Some(&refresh.user_id),
            client_id,
            "client_secret_version_changed",
        )
        .await;
    }

    // 校验、轮换签发和 Redis TTL/墓碑共用同一次时钟读取。再读一次（或绕回墙钟）
    // 会让「validate 刚放行」的后继 token 按另一个时刻写 TTL，键可能立刻过期
    // （Issue #366）。
    let now = state.clock.now();
    if refresh.validate(client_id, now).is_err() {
        return record_and_return_invalid(
            state,
            Some(&refresh.user_id),
            client_id,
            "invalid_token",
        )
        .await;
    }
    match state
        .revocations
        .is_consent_revoked(&refresh.user_id, client_id)
        .await
    {
        Ok(true) => return Err(OAuthError::invalid_refresh_grant().into()),
        Ok(false) => {}
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to check OAuth consent revocation");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    }

    let Ok(user_id) = refresh.user_id.parse::<UserId>() else {
        return Err(OAuthError::invalid_refresh_grant().into());
    };
    match state
        .consents
        .has_scopes(user_id, client_id, &refresh.scopes)
        .await
    {
        Ok(true) => {}
        Ok(false) => return Err(OAuthError::invalid_refresh_grant().into()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to check refresh token consent");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    }
    // Issue #409：凭据代际比对（见 `RefreshToken::is_bound_to_session_epoch`）。
    // `session_epoch` 是「撤销该用户全部凭据」的单一水位，会话校验每次查找都
    // 在比对；TOTP 重置只踢 Cookie 会话、旧 Refresh Token 仍可兑换的漏洞，
    // 靠这道判定关闭。
    let current_epoch = match active_user_epoch(state, &refresh.user_id).await {
        Ok(Some(epoch)) => epoch,
        Ok(None) => return Err(OAuthError::invalid_refresh_grant().into()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load refresh token user credentials");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    };
    if !refresh.is_bound_to_session_epoch(current_epoch) {
        // 旧格式 payload 缺失 epoch（`None`），无法证明签发时刻先于任何撤销
        // 操作，fail-closed 拒绝：升级后客户端重新走授权流程换取新代际凭据。
        let reason = if refresh.session_epoch.is_none() {
            "refresh_token_epoch_required"
        } else {
            "user_credentials_revoked"
        };
        return record_and_return_invalid(state, Some(&refresh.user_id), client_id, reason).await;
    }

    let scopes = select_scopes(request.scope.as_deref(), &refresh.scopes)?;
    // Rotation inherits issued_at/family_id/session_epoch and stamps the
    // authenticated Client Secret generation, including for legacy unversioned
    // tokens. The inherited epoch keeps the successor in the same credential
    // generation: re-reading it here would let a revocation that lands between
    // the check above and this rotation be stamped away (Issue #409).
    let next_refresh = refresh.rotate_at_with_client_secret_version(
        scopes.clone(),
        authenticated.client_secret_version(),
        now,
    );
    let token = issue_token_response(
        state,
        &refresh.user_id,
        client_id,
        &scopes,
        Some(next_refresh.value.clone()),
        None,
        None,
    )
    .await?;

    // This shared PostgreSQL row lock is the cross-instance ordering boundary
    // with Client Secret rotation. It remains held until Redis has atomically
    // replaced the old token with its successor.
    let issuance_guard = match state.clients.acquire_issuance_guard(&authenticated).await {
        Ok(Some(guard)) => guard,
        Ok(None) => return Err(OAuthError::InvalidClient.into()),
        Err(database_error) => {
            tracing::error!(
                error = %database_error,
                "failed to fence refresh-token issuance"
            );
            return Err(OAuthError::temporarily_unavailable().into());
        }
    };

    // All checks and token issuance happen before this CAS. It is the single credential
    // consumption boundary, and remains atomic with tombstone creation in the store.
    let rotation = state
        .refresh_tokens
        .rotate_if_matches_at(refresh_value, &refresh, &next_refresh, now)
        .await;
    let rotated = rotation
        .as_ref()
        .is_ok_and(|outcome| *outcome == RotationOutcome::Rotated);
    if let Err(release_error) = issuance_guard.release().await {
        tracing::error!(
            error = %release_error,
            client_id = %client_id,
            "failed to release Client credential issuance fence after refresh rotation"
        );
        if rotated {
            rollback_rotation(state, client_id, &next_refresh, &refresh).await;
        }
        return Err(OAuthError::temporarily_unavailable().into());
    }
    match rotation {
        Ok(RotationOutcome::Rotated) => {
            if record_token_event(
                state,
                Some(&refresh.user_id),
                "token_refresh",
                Some(client_id),
                "success",
            )
            .await
            .is_err()
            {
                rollback_rotation(state, client_id, &next_refresh, &refresh).await;
                return Err(RefreshExchangeError::ServerError);
            }
            Ok(token)
        }
        // Losing the CAS means this exact token was already consumed between the lookup and
        // the swap. That is a replay, not a benign race: two parties held the same credential
        // and the loser must not keep a usable grant (Issue #293). The token payload we read
        // is server-side state, so the family is located without trusting the tombstone.
        Ok(RotationOutcome::CasMismatch) => {
            // 旧格式 token 的 payload 里 family 是空串，但家族可以由 token 值
            // 确定性派生（Issue #313）。CAS 失败说明轮换已经把后继写进了那个
            // 家族，撤销必须命中后继——否则只删这个已死的旧值，泄露凭据的
            // 家族撤销被绕过。
            let family_id = refresh.family_identifier();
            revoke_family_after_replay(
                state,
                ReplayContext {
                    client_id,
                    user_id: &refresh.user_id,
                    family_id: &family_id,
                    replayed_value: refresh_value,
                },
            )
            .await
        }
        // The grant died while this request was in flight. Nothing to revoke and nothing to
        // report as a leak: the family tombstone already recorded whatever killed it.
        Ok(RotationOutcome::FamilyRevoked) => {
            record_and_return_invalid(state, Some(&refresh.user_id), client_id, "token_revoked")
                .await
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to atomically rotate refresh token");
            Err(OAuthError::temporarily_unavailable().into())
        }
    }
}

/// 选择本次刷新使用的 scope 集合（RFC 6749 §6）。
///
/// `scope` 省略或去空白后为空时沿用原授权：`scope=`、`scope=%20` 与完全不带
/// 该参数在表单解码后无法区分，把它当成「降级到零权限」会让客户端拿到没有
/// 任何权限、且轮换后永久丢失 scope 的 token（Issue #282）。缩小 scope 必须
/// 显式列出要保留的值。
fn select_scopes(
    requested_scope: Option<&str>,
    original_scopes: &[String],
) -> Result<Vec<String>, OAuthError> {
    let requested = requested_scope
        .map(|scope| {
            scope
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|scopes| !scopes.is_empty());
    let Some(requested) = requested else {
        return Ok(original_scopes.to_owned());
    };
    if requested
        .iter()
        .any(|scope| !original_scopes.contains(scope))
    {
        return Err(OAuthError::bad_request(
            "invalid_scope",
            "requested scope exceeds original grant",
        ));
    }
    Ok(requested)
}

async fn handle_missing_refresh_token(
    state: &AppState,
    client_id: &str,
    refresh_value: &str,
) -> Result<TokenResponse, RefreshExchangeError> {
    let tombstone = match state.refresh_tokens.read_tombstone(refresh_value).await {
        Ok(tombstone) => tombstone,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to read refresh token tombstone");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    };
    // 没有墓碑说明这个值从未被本服务签发，或者已经超出重放检测窗口。
    let Some(tombstone) = tombstone else {
        return record_and_return_invalid(state, None, client_id, "invalid_token").await;
    };
    match classify_tombstone(&tombstone, client_id) {
        TombstoneDisposition::Replay => {
            // 升级前写入的旧墓碑没有 family_id（旧格式轮换不记录后继家族）：
            // 由提交值哈希派生家族标识，与轮换时写入后继的家族一致（#313）。
            let family_id =
                RefreshToken::resolve_family_identifier(&tombstone.family_id, refresh_value);
            revoke_family_after_replay(
                state,
                ReplayContext {
                    client_id,
                    user_id: &tombstone.user_id,
                    family_id: &family_id,
                    replayed_value: refresh_value,
                },
            )
            .await
        }
        TombstoneDisposition::AlreadyDead => {
            record_and_return_invalid(state, Some(&tombstone.user_id), client_id, "token_revoked")
                .await
        }
        TombstoneDisposition::ForeignClient => {
            // Do not record the submitted token value; it is a credential.
            tracing::warn!(
                event = "refresh.replay_client_mismatch",
                client_id = %client_id,
                "refresh token replay attempt with mismatched client_id; \
                 refusing without revoking the owning family"
            );
            record_and_return_invalid(state, None, client_id, "invalid_token").await
        }
    }
}

/// 撤销一次已经落库、但响应没能发出去的轮换（Issue #290）。
///
/// 客户端只会收到错误响应，它手里仍然是 `previous`，所以必须让 `previous`
/// 重新可用、同时让 `issued` 彻底失效。删除与恢复必须原子完成：分两步做时
/// 删除失败仍会恢复 `previous`，family 里就同时留下两个可兑换凭据，其中一个
/// 客户端永远拿不到、却仍能被兑换。
async fn rollback_rotation(
    state: &AppState,
    client_id: &str,
    issued: &RefreshToken,
    previous: &RefreshToken,
) {
    match state
        .refresh_tokens
        .rollback_rotation(issued, previous)
        .await
    {
        Ok(RotationOutcome::Rotated) => {}
        // 新 token 已经不在（并发消费或已过期），或整个 family 已被撤销。
        // 两种情况下恢复 previous 都会给已死的 grant 造出一个活凭据，
        // 只能让客户端重新走授权流程。
        Ok(outcome) => tracing::warn!(
            event = "refresh.rotation_rollback_skipped",
            client_id = %client_id,
            family_id = %issued.family_id,
            outcome = ?outcome,
            "refresh rotation rollback skipped: the issued token can no longer be swapped back"
        ),
        Err(store_error) => tracing::error!(
            event = "refresh.rotation_rollback_failed",
            error = %store_error,
            client_id = %client_id,
            family_id = %issued.family_id,
            "failed to roll back refresh rotation after audit persistence failure"
        ),
    }
}

async fn record_and_return_invalid(
    state: &AppState,
    user_id: Option<&str>,
    client_id: &str,
    reason: &str,
) -> Result<TokenResponse, RefreshExchangeError> {
    record_token_event_best_effort(
        state,
        user_id,
        "token_refresh_failure",
        Some(client_id),
        reason,
    )
    .await;
    Err(OAuthError::invalid_refresh_grant().into())
}

#[cfg(test)]
#[path = "refresh_use_case_tests.rs"]
mod tests;
