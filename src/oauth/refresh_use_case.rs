use super::{OAuthError, RefreshExchangeError, TokenRequest, TokenResponse, issue_token_response};
use crate::{state::AppState, users::domain::UserId};

use super::super::{
    refresh::RefreshToken,
    refresh_store::{Tombstone, TombstoneState},
    session::active_user_id,
    token_security::{record_token_event, record_token_event_best_effort},
};

/// Exchange a refresh token after the token endpoint has authenticated the client.
pub(super) async fn exchange_refresh_token(
    state: &AppState,
    request: TokenRequest,
) -> Result<TokenResponse, RefreshExchangeError> {
    let Some(refresh_value) = request.refresh_token.as_deref() else {
        return Err(OAuthError::bad_request("invalid_request", "refresh_token is required").into());
    };
    let Some(client_id) = request.client_id.as_deref() else {
        return Err(OAuthError::InvalidClient.into());
    };
    let refresh = match state.refresh_tokens.find(refresh_value).await {
        Ok(Some(refresh)) => refresh,
        Ok(None) => {
            // A missing token may be either unknown or a replay of a normally rotated token.
            return handle_missing_refresh_token(state, client_id, refresh_value).await;
        }
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to retrieve refresh token");
            return Err(OAuthError::temporarily_unavailable().into());
        }
    };

    if refresh
        .validate(client_id, time::OffsetDateTime::now_utc())
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
    // rotate() inherits issued_at and family_id so absolute lifetime and replay revocation
    // semantics survive rotation.
    let next_refresh = refresh.rotate(scopes.clone());
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

    // All checks and token issuance happen before this CAS. It is the single credential
    // consumption boundary, and remains atomic with tombstone creation in the store.
    match state
        .refresh_tokens
        .rotate_if_matches(refresh_value, &refresh, &next_refresh)
        .await
    {
        Ok(true) => {
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
        Ok(false) => {
            // A lost CAS race is classified from the matching tombstone: a recent consumed
            // marker is a bounded concurrency race, while an old one is a replay signal.
            let tombstone = match state.refresh_tokens.read_tombstone(refresh_value).await {
                Ok(tombstone) => tombstone,
                Err(store_error) => {
                    tracing::error!(error = %store_error, "failed to read refresh token tombstone");
                    return Err(OAuthError::temporarily_unavailable().into());
                }
            };
            match tombstone {
                Some(tombstone) if tombstone.client_id == client_id => {
                    match classify_tombstone(&tombstone, time::OffsetDateTime::now_utc()) {
                        TombstoneDisposition::ConcurrentRace => {
                            record_and_return_invalid(
                                state,
                                Some(&refresh.user_id),
                                client_id,
                                "token_race",
                            )
                            .await
                        }
                        TombstoneDisposition::Replay => {
                            revoke_family_after_replay(state, client_id, refresh_value, &tombstone)
                                .await
                        }
                        TombstoneDisposition::ExplicitRevoke
                        | TombstoneDisposition::FamilyRevoked => {
                            record_and_return_invalid(
                                state,
                                Some(&refresh.user_id),
                                client_id,
                                "token_revoked",
                            )
                            .await
                        }
                    }
                }
                _ => {
                    // A missing tombstone is a narrow race in which the family cannot be
                    // located, so reject only this request.
                    tracing::warn!(
                        client_id = %client_id,
                        "refresh rotation lost CAS race but tombstone is missing; \
                         cannot revoke family"
                    );
                    record_and_return_invalid(
                        state,
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
    // 并发刷新落到这条路径还是 CAS loser 路径，只取决于本请求的 find 发生在
    // 胜者的轮换之前还是之后——两者都是同一批并发请求。分类只看墓碑本身，
    // 不看请求走了哪条路（Issue #278）。
    match state.refresh_tokens.read_tombstone(refresh_value).await {
        Ok(Some(tombstone)) if tombstone.client_id == client_id => {
            match classify_tombstone(&tombstone, time::OffsetDateTime::now_utc()) {
                TombstoneDisposition::Replay => {
                    revoke_family_after_replay(state, client_id, refresh_value, &tombstone).await
                }
                TombstoneDisposition::ConcurrentRace => {
                    record_and_return_invalid(
                        state,
                        Some(&tombstone.user_id),
                        client_id,
                        "token_race",
                    )
                    .await
                }
                TombstoneDisposition::ExplicitRevoke | TombstoneDisposition::FamilyRevoked => {
                    record_and_return_invalid(
                        state,
                        Some(&tombstone.user_id),
                        client_id,
                        "token_revoked",
                    )
                    .await
                }
            }
        }
        Ok(Some(_)) => {
            // Do not record the submitted token value; it is a credential.
            tracing::warn!(
                client_id = %client_id,
                "refresh token replay attempt with mismatched client_id; \
                 refusing without revoking the owning family"
            );
            record_and_return_invalid(state, None, client_id, "invalid_token").await
        }
        // No tombstone means an unknown token or one outside the replay-detection window.
        Ok(None) => record_and_return_invalid(state, None, client_id, "invalid_token").await,
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to read refresh token tombstone");
            Err(OAuthError::temporarily_unavailable().into())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TombstoneDisposition {
    ConcurrentRace,
    Replay,
    ExplicitRevoke,
    FamilyRevoked,
}

/// 把墓碑映射成处置方式（RFC 9700 §4.14.2 的 replay 判定）。
///
/// 只依赖墓碑状态和消费时刻，不依赖调用方走了哪条缺失路径：并发刷新中的
/// 落败请求可能在 CAS 处失败，也可能在 `find` 处就已经看不到 token，
/// 按路径区分只会让正常并发随机触发 family 撤销。
fn classify_tombstone(tombstone: &Tombstone, now: time::OffsetDateTime) -> TombstoneDisposition {
    match tombstone.state {
        // 消费墓碑落在并发窗口内：拒绝当次请求，但不撤销 family。
        TombstoneState::Consumed if tombstone.is_recent_consumption(now) => {
            TombstoneDisposition::ConcurrentRace
        }
        TombstoneState::Consumed => TombstoneDisposition::Replay,
        TombstoneState::ExplicitRevoke => TombstoneDisposition::ExplicitRevoke,
        TombstoneState::FamilyRevoked => TombstoneDisposition::FamilyRevoked,
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
        Ok(true) => {}
        // 新 token 已经不在（并发消费或已过期）。此时恢复 previous 会造出第二个
        // 活凭据，只能让客户端重新走授权流程。
        Ok(false) => tracing::warn!(
            client_id = %client_id,
            family_id = %issued.family_id,
            "refresh rotation rollback skipped: the issued token is already gone"
        ),
        Err(store_error) => tracing::error!(
            error = %store_error,
            client_id = %client_id,
            family_id = %issued.family_id,
            "failed to roll back refresh rotation after audit persistence failure"
        ),
    }
}

async fn revoke_family_after_replay(
    state: &AppState,
    client_id: &str,
    replayed_value: &str,
    tombstone: &Tombstone,
) -> Result<TokenResponse, RefreshExchangeError> {
    match state
        .refresh_tokens
        .revoke_family_after_replay(
            &tombstone.family_id,
            client_id,
            &tombstone.user_id,
            replayed_value,
        )
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
