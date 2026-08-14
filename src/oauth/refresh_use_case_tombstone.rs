//! 刷新用例中「凭据已不在 Redis」时的处置：墓碑分类、重放撤销与审计。
//!
//! 拆成独立文件是因为重放判定（RFC 9700 §4.14.2）与键消失（Issue #312）
//! 的语义约束需要大量说明，混在 `refresh_use_case.rs` 的兑换主流程里会让
//! 它越过源文件长度门槛。
//!
//! 这里是 `exchange_refresh_token` 的辅助逻辑：作为子模块，它能访问父模块
//! 私有的 `OAuthError` / `RefreshExchangeError`，无需把错误类型提升为
//! crate 可见。
//!
//! 重放判定与 family 撤销的编排（`TombstoneDisposition` /
//! `classify_tombstone` / `revoke_family_after_replay` / `ReplayContext`）
//! 由兄弟模块 `refresh_use_case_replay.rs`（Issue #313）统一提供，本模块
//! 只负责「键已消失」时的查找与分流，避免同一套安全语义出现两份实现。

use super::super::super::{
    refresh::RefreshToken, refresh_store::Tombstone, token_security::record_token_event_best_effort,
};
use super::super::{OAuthError, RefreshExchangeError, TokenResponse};
use super::replay::{
    ReplayContext, TombstoneDisposition, classify_tombstone, revoke_family_after_replay,
};
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
            // 升级前写入的旧墓碑没有 family_id（旧格式轮换不记录后继家族）：
            // 由提交值哈希派生家族标识，与轮换时写入后继的家族一致（#313）。
            let family_id =
                RefreshToken::resolve_family_identifier(&tombstone.family_id, submitted_value);
            revoke_family_after_replay(
                state,
                ReplayContext {
                    client_id,
                    user_id: &tombstone.user_id,
                    family_id: &family_id,
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

/// 键仍在但值已变：必定是重放（Issue #293）。
///
/// 与键消失（[`handle_vanished_refresh_token`]）不同，这里没有歧义，直接按
/// 重放撤销 family。payload 是服务端状态，family 定位不依赖墓碑；旧格式
/// token 的 payload 里 family 为空串，由 token 值确定性派生（Issue #313）。
pub(super) async fn revoke_family_after_cas_mismatch(
    state: &AppState,
    client_id: &str,
    refresh: &RefreshToken,
    replayed_value: &str,
) -> Result<TokenResponse, RefreshExchangeError> {
    let family_id = refresh.family_identifier();
    revoke_family_after_replay(
        state,
        ReplayContext {
            client_id,
            user_id: &refresh.user_id,
            family_id: &family_id,
            replayed_value,
        },
    )
    .await
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
        crate::audit::AuditAction::TokenRefreshFailure,
        Some(client_id),
        reason,
    )
    .await;
    Err(OAuthError::invalid_refresh_grant().into())
}
