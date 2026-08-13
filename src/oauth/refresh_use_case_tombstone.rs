//! 刷新用例中「凭据已不在 Redis」时的处置：墓碑分类、重放撤销与审计。
//!
//! 拆成独立文件是因为重放判定（RFC 9700 §4.14.2）与键消失（Issue #312）
//! 的语义约束需要大量说明，混在 `refresh_use_case.rs` 的兑换主流程里会让
//! 它越过源文件长度门槛。
//!
//! 这里是 `exchange_refresh_token` 的辅助逻辑：作为子模块，它能访问父模块
//! 私有的 `OAuthError` / `RefreshExchangeError`，无需把错误类型提升为
//! crate 可见。

use super::super::super::{
    refresh::RefreshToken,
    refresh_store::{FamilyRevocation, Tombstone, TombstoneState},
    token_security::{
        record_token_event_best_effort, record_token_event_with_metadata_best_effort,
    },
};
use super::super::{OAuthError, RefreshExchangeError, TokenResponse};
use crate::state::AppState;

/// 处理 `find` 未命中的提交：这个值可能从未被签发，也可能是已被消费的凭据
/// 重放（键已删除、只剩墓碑），还可能只是超出了重放检测窗口。
pub(super) async fn handle_missing_refresh_token(
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
    // 没有墓碑说明这个值从未被本服务签发，或者已经超出重放检测窗口；
    // 此时也没有 payload 可用来记录归属用户。
    dispose_by_tombstone(state, tombstone.as_ref(), client_id, refresh_value, None).await
}

/// 处理「轮换 CAS 时键消失」的提交（Issue #312）。
///
/// `find` 刚放行的键在 CAS 前消失有两种可能：恶性的是已被并发消费（重放），
/// 良性的是滑动/绝对期限边界过期、Redis 驱逐或应用与 Redis 时钟偏差——
/// 用例在 `find` 与轮换之间隔着 consent 检查、scope 校验、DB 往返和 JWT
/// 签发，这段时间足够键到期。脚本只回答「键不在了」，是否重放由墓碑决定。
///
/// 与 [`handle_missing_refresh_token`] 不同，这里手里有刚读到的 payload，
/// 无墓碑时仍能记录归属用户；处置本身共用 [`dispose_by_tombstone`]：
/// 有 `Consumed` 墓碑才是重放并撤销 family，没有墓碑绝不能撤销。
pub(super) async fn handle_vanished_refresh_token(
    state: &AppState,
    client_id: &str,
    refresh_value: &str,
    refresh: &RefreshToken,
) -> Result<TokenResponse, RefreshExchangeError> {
    let tombstone = match state.refresh_tokens.read_tombstone(refresh_value).await {
        Ok(tombstone) => tombstone,
        Err(store_error) => {
            tracing::error!(
                error = %store_error,
                "failed to read refresh token tombstone after the rotation key vanished"
            );
            return Err(OAuthError::temporarily_unavailable().into());
        }
    };
    dispose_by_tombstone(
        state,
        tombstone.as_ref(),
        client_id,
        refresh_value,
        Some(&refresh.user_id),
    )
    .await
}

/// 凭据已不在 Redis 时按墓碑处置。
///
/// 墓碑是「这个值曾经合法存在过」的唯一证据：
/// - `Consumed` → 重放，撤销整个 family（RFC 9700 §4.14.2）
/// - `ExplicitRevoke` / `FamilyRevoked` → 凭据已死，只拒绝当次请求
/// - 无墓碑 → 从未签发或已超出重放检测窗口，只拒绝当次请求
/// - 归属 Client 不符 → 拒绝且绝不撤销别人的 family（Issue #110）
///
/// `known_user_id` 只在「无墓碑」时用于审计：`find` 未命中路径没有 payload
/// 可查，键消失路径则保留刚读到的归属用户。
async fn dispose_by_tombstone(
    state: &AppState,
    tombstone: Option<&Tombstone>,
    client_id: &str,
    submitted_value: &str,
    known_user_id: Option<&str>,
) -> Result<TokenResponse, RefreshExchangeError> {
    let Some(tombstone) = tombstone else {
        return record_and_return_invalid(state, known_user_id, client_id, "invalid_token").await;
    };
    match classify_tombstone(tombstone, client_id) {
        TombstoneDisposition::Replay => {
            revoke_family_after_replay(
                state,
                ReplayContext {
                    client_id,
                    user_id: &tombstone.user_id,
                    family_id: &tombstone.family_id,
                    replayed_value: submitted_value,
                },
            )
            .await
        }
        TombstoneDisposition::AlreadyDead => {
            record_and_return_invalid(state, Some(&tombstone.user_id), client_id, "token_revoked")
                .await
        }
        TombstoneDisposition::ForeignClient => {
            // 不记录提交的 token 值：它是凭据。
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

/// 键仍在但值已变：必定是重放（Issue #293）。
///
/// 与键消失（[`handle_vanished_refresh_token`]）不同，这里没有歧义，直接按
/// 重放撤销 family。payload 是服务端状态，family 定位不依赖墓碑。
pub(super) async fn revoke_family_after_cas_mismatch(
    state: &AppState,
    client_id: &str,
    refresh: &RefreshToken,
    replayed_value: &str,
) -> Result<TokenResponse, RefreshExchangeError> {
    revoke_family_after_replay(
        state,
        ReplayContext {
            client_id,
            user_id: &refresh.user_id,
            family_id: &refresh.family_id,
            replayed_value,
        },
    )
    .await
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

pub(super) async fn record_and_return_invalid(
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
