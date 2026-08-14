use super::{
    OAuthError, RefreshExchangeError, TokenIssueParams, TokenRequest, TokenResponse,
    issue_token_response,
};
use crate::{clients::service::AuthenticatedClient, config::IssuerUrl, state::AppState};

use super::super::{
    grant_gate::{GrantGateError, effective_grant_scopes},
    refresh::RefreshToken,
    refresh_store::RotationOutcome,
    session::active_user_epoch,
    token_security::record_token_event,
};

/// 凭据已不在 Redis 时的处置（墓碑分类、重放撤销、审计）拆在子模块里，
/// 保持兑换主流程可审查（沿用 `refresh_store_revocation.rs` 的模式）。
#[path = "refresh_use_case_tombstone.rs"]
mod tombstone;
use tombstone::{
    handle_missing_refresh_token, handle_vanished_refresh_token, record_and_return_invalid,
    revoke_family_after_cas_mismatch,
};

// 重放处置（墓碑分类与 family 撤销）拆在独立文件：安全语义说明密度较高，
// 混在主用例里会让本文件越过源文件长度门槛。
#[path = "refresh_use_case_replay.rs"]
mod replay;

/// Exchange a refresh token after the token endpoint has authenticated the client.
pub(super) async fn exchange_refresh_token(
    state: &AppState,
    issuer: &IssuerUrl,
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
    // 兑换时刻的授权准入：撤销状态、Client 可用性、当前注册 scope 与同意覆盖
    // 由 `grant_gate` 统一判定，三条兑换路径共用同一实现。此前这里只查
    // consent，不复核 Client 当前注册的 scope，管理员缩减 scope 后旧授权仍按
    // 旧集合续签（Issue #421）。
    //
    // `granted` 是本次兑换允许的上界：闸门收窄后的集合才是 `select_scopes`
    // 可选择的范围。
    let granted =
        match effective_grant_scopes(state, &refresh.user_id, client_id, &refresh.scopes).await {
            Ok(granted) => granted,
            Err(GrantGateError::Denied(reason)) => {
                return record_and_return_invalid(state, Some(&refresh.user_id), client_id, reason)
                    .await;
            }
            Err(GrantGateError::Unavailable(_)) => {
                return Err(OAuthError::temporarily_unavailable().into());
            }
        };
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

    let scopes = select_scopes(request.scope.as_deref(), &granted)?;
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
        TokenIssueParams {
            issuer,
            user_id: &refresh.user_id,
            client_id,
            scopes: &scopes,
            refresh_token: Some(next_refresh.value.clone()),
            nonce: None,
            auth_time: None,
        },
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
                crate::audit::AuditAction::TokenRefresh,
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
        // 键仍在但值不匹配：这个 token 一定是在查找与交换之间被另一个持有者
        // 消费了。那是重放，不是良性竞态：两个持有者拿着同一份凭据，输家不能
        // 保留可用的 grant（Issue #293）。键消失的歧义情况（可能是过期/驱逐/
        // 时钟偏差）由 KeyMissing 分支查墓碑区分，不走这里。
        Ok(RotationOutcome::CasMismatch) => {
            revoke_family_after_cas_mismatch(state, client_id, &refresh, refresh_value).await
        }
        // 键在 `find` 与 CAS 之间消失了（Issue #312）。脚本只回答「键不在」，
        // 不回答「为什么」：已被并发消费是重放，过期/驱逐/时钟偏差是良性。
        // 区分依据是墓碑，交给专门的处置函数；没有 `Consumed` 墓碑时绝不能
        // 撤销整个 family。
        Ok(RotationOutcome::KeyMissing) => {
            handle_vanished_refresh_token(state, client_id, refresh_value, &refresh).await
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

#[cfg(test)]
#[path = "refresh_use_case_tests.rs"]
mod tests;
