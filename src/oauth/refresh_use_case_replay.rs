//! Refresh Token 重放处置：墓碑分类与 family 撤销的编排。
//!
//! 从 `refresh_use_case.rs` 拆出：重放判定与撤销的安全语义说明密度较高，
//! 混在主用例里会让 `refresh_use_case.rs` 越过源文件长度门槛。

use super::super::super::{
    refresh_store::{FamilyRevocation, Tombstone, TombstoneState},
    token_security::{
        record_token_event_best_effort, record_token_event_with_metadata_best_effort,
    },
};
use super::super::{OAuthError, RefreshExchangeError, TokenResponse};
use crate::state::AppState;

/// 一次重放处置所需的、全部来自服务端状态的上下文。
///
/// `family_id` / `user_id` 只能来自 token payload 或墓碑，绝不能取自请求参数：
/// 否则任何 Client 都能指定别人的 family 触发撤销。
pub(super) struct ReplayContext<'a> {
    pub(super) client_id: &'a str,
    pub(super) user_id: &'a str,
    pub(super) family_id: &'a str,
    pub(super) replayed_value: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum TombstoneDisposition {
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
pub(super) fn classify_tombstone(tombstone: &Tombstone, client_id: &str) -> TombstoneDisposition {
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

/// 检测到重放后撤销整个 family，并把结果落成可检索的安全事件。
///
/// 撤销失败必须 fail closed（Issue #292）。此前的实现只打一条日志就继续返回
/// `invalid_grant`，于是「family 撤销没做成」和「这个 token 确实无效」在协议
/// 层完全同形：攻击者拿到的仍是标准的 invalid_grant，而被泄露的 family 里
/// 其它成员还活着，运维侧也没有任何区别于日常拒绝的信号。现在返回
/// `temporarily_unavailable`，明确告诉调用方这是服务端状态未收敛，
/// 并记录独立的审计事件供检索。
pub(super) async fn revoke_family_after_replay(
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
                crate::audit::AuditAction::TokenRefreshFailure,
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
            crate::audit::AuditAction::TokenRefreshFailure,
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
        crate::audit::AuditAction::TokenRefreshFailure,
        Some(context.client_id),
        serde_json::json!({
            "reason": "refresh_replay_detected",
            "family_id": context.family_id,
            "revoked_refresh_tokens": revocation.revoked_tokens,
        }),
    )
    .await;
}
