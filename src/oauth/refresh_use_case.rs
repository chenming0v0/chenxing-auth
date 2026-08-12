use super::{OAuthError, RefreshExchangeError, TokenRequest, TokenResponse, issue_token_response};
use crate::{clients::service::AuthenticatedClient, state::AppState, users::domain::UserId};

use super::super::{
    refresh::RefreshToken,
    refresh_store::{FamilyRevocation, RotationOutcome, Tombstone, TombstoneState},
    session::active_user_id,
    token_security::{
        record_token_event, record_token_event_best_effort,
        record_token_event_with_metadata_best_effort,
    },
};

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

    if refresh
        .validate(client_id, state.clock.now())
        .is_err()
    {
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
    match active_user_id(state, &refresh.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(OAuthError::invalid_refresh_grant().into()),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to load refresh token user");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    }

    let scopes = select_scopes(request.scope.as_deref(), &refresh.scopes)?;
    // Rotation inherits issued_at/family_id and stamps the authenticated Client
    // Secret generation, including for legacy unversioned tokens.
    let next_refresh = refresh.rotate_at_with_client_secret_version(
        scopes.clone(),
        authenticated.client_secret_version(),
        state.clock.now(),
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
        .rotate_if_matches(refresh_value, &refresh, &next_refresh)
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
            revoke_family_after_replay(
                state,
                ReplayContext {
                    client_id,
                    user_id: &refresh.user_id,
                    family_id: &refresh.family_id,
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
            revoke_family_after_replay(
                state,
                ReplayContext {
                    client_id,
                    user_id: &tombstone.user_id,
                    family_id: &tombstone.family_id,
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

#[derive(Debug, PartialEq, Eq)]
enum TombstoneDisposition {
    /// 已消费的凭据被再次提交：RFC 9700 §4.14.2 的重放，撤销整个 family。
    Replay,
    /// 凭据已经因主动撤销或 family 撤销而死亡，只拒绝当次请求。
    AlreadyDead,
    /// 提交者不是凭据的归属 Client，拒绝且绝不撤销别人的 family。
    ForeignClient,
}

/// 把墓碑映射成处置方式（RFC 9700 §4.14.2 的重放判定）。
///
/// 判定只有两个输入：墓碑归属的 Client 和墓碑状态。这里**没有**时间窗口。
///
/// 曾经存在过一个 5 秒宽限窗口，把窗口内重复提交同一个已消费 token 当成
/// 「正常并发刷新」而放过。它的代价是：攻击者窃取凭据后只要在合法客户端刷新
/// 后的 5 秒内跟着提交同一个 token，就能得到一次「不撤销 family」的免费尝试，
/// 而 family 撤销正是检测凭据泄露的唯一手段（Issue #293）。窗口两侧都不安全
/// ——它同时也让「客户端自己并发提交同一 token」这种客户端 bug 被静默容忍。
///
/// 现在的语义是单次使用的字面含义：`Consumed` 墓碑 + 再次提交 = 重放。
/// 正常客户端永远不会重复提交同一个 refresh token，因为轮换后它手里已经是
/// 新值；重复提交要么是客户端并发 bug，要么是凭据泄露，两者都应该让 grant
/// 失效并要求重新授权。
fn classify_tombstone(tombstone: &Tombstone, client_id: &str) -> TombstoneDisposition {
    if tombstone.client_id != client_id {
        return TombstoneDisposition::ForeignClient;
    }
    match tombstone.state {
        TombstoneState::Consumed => TombstoneDisposition::Replay,
        TombstoneState::ExplicitRevoke | TombstoneState::FamilyRevoked => {
            TombstoneDisposition::AlreadyDead
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

/// 一次重放处置所需的、全部来自服务端状态的上下文。
///
/// `family_id` / `user_id` 只能来自 token payload 或墓碑，绝不能取自请求参数：
/// 否则任何 Client 都能指定别人的 family 触发撤销。
struct ReplayContext<'a> {
    client_id: &'a str,
    user_id: &'a str,
    family_id: &'a str,
    replayed_value: &'a str,
}

/// 检测到重放后撤销整个 family，并把结果落成可检索的安全事件。
///
/// 撤销失败必须 fail closed（Issue #292）。此前的实现只打一条日志就继续返回
/// `invalid_grant`，于是「family 撤销没做成」和「这个 token 确实无效」在协议
/// 层完全同形：攻击者拿到的仍是标准的 invalid_grant，而被泄露的 family 里
/// 其它成员还活着，运维侧也没有任何区别于日常拒绝的信号。现在返回
/// `temporarily_unavailable`，明确告诉调用方这是服务端状态未收敛，
/// 并记录独立的审计事件供检索。
async fn revoke_family_after_replay(
    state: &AppState,
    context: ReplayContext<'_>,
) -> Result<TokenResponse, RefreshExchangeError> {
    let revocation = match state
        .refresh_tokens
        .revoke_family_after_replay(
            context.family_id,
            context.client_id,
            context.user_id,
            context.replayed_value,
        )
        .await
    {
        Ok(revocation) => revocation,
        Err(store_error) => {
            tracing::error!(
                event = "refresh.family_revocation_failed",
                error = %store_error,
                client_id = %context.client_id,
                family_id = %context.family_id,
                "refresh token replay detected but the family revocation failed; \
                 refusing the request without pretending the grant is merely invalid"
            );
            record_token_event_with_metadata_best_effort(
                state,
                Some(context.user_id),
                "token_refresh_failure",
                Some(context.client_id),
                serde_json::json!({
                    "reason": "refresh_family_revocation_failed",
                    "family_id": context.family_id,
                }),
            )
            .await;
            return Err(OAuthError::temporarily_unavailable().into());
        }
    };
    report_replay(state, &context, revocation).await;
    Err(OAuthError::invalid_refresh_grant().into())
}

/// 记录重放处置结果。
///
/// 审计写入用 best-effort：family 撤销已经不可逆地完成，把审计故障翻译成另一个
/// HTTP 状态只会诱导调用方重试一个不会改变结果的请求。`audit.best_effort_failure`
/// 与这里的 tracing 事件共同保留人工补录所需的上下文。
async fn report_replay(
    state: &AppState,
    context: &ReplayContext<'_>,
    revocation: FamilyRevocation,
) {
    if revocation.already_revoked {
        // 同一次重放的并发请求，或对一个已死 family 的再次提交：
        // 撤销早已完成，不重复上报安全事件。
        record_token_event_best_effort(
            state,
            Some(context.user_id),
            "token_refresh_failure",
            Some(context.client_id),
            "token_revoked",
        )
        .await;
        return;
    }
    tracing::warn!(
        event = "refresh.replay_detected",
        client_id = %context.client_id,
        family_id = %context.family_id,
        revoked_refresh_tokens = revocation.revoked_tokens,
        "refresh token replay detected; revoked entire token family"
    );
    record_token_event_with_metadata_best_effort(
        state,
        Some(context.user_id),
        "token_refresh_failure",
        Some(context.client_id),
        serde_json::json!({
            "reason": "refresh_replay_detected",
            "family_id": context.family_id,
            "revoked_refresh_tokens": revocation.revoked_tokens,
        }),
    )
    .await;
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
