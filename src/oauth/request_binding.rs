//! Pending 授权请求与浏览器会话的绑定语义（唯一实现）。
//!
//! # 为什么只有一份实现
//!
//! 「把 pending 请求绑到某个会话」这件事有两个入口：SPA 登录后调用的
//! `/bind` 端点，和外部身份源回调后的服务端内部绑定。两处曾各写一遍
//! CAS + holder 校验，导致同一条安全规则有两个版本，其中一个改了另一个
//! 不改（#270 就是这么来的）。现在两处都调用 [`bind_pending_request`]。
//!
//! # 安全模型：holder 是所有权凭据，session 绑定是派生状态
//!
//! 两个字段的职责必须分清，否则会得出「会话过期就不能再绑」的错误结论：
//!
//! - `holder_hash`：**所有权凭据**。原值只存在于发起 `/oauth/authorize`
//!   的那个浏览器的 HttpOnly Cookie 里，Redis 只存摘要。它回答的是
//!   「你是不是发起这次授权的浏览器」。
//! - `session_token_hash`：**派生状态**。它记录「当前由哪个会话持有这条
//!   请求」，供 `inspect` / `decide` 校验，并让签发的授权码继承会话绑定。
//!   它回答的不是所有权问题。
//!
//! 因此受控重绑是安全的：holder 校验通过 ⇒ 调用者就是发起授权的浏览器；
//! 调用方另外校验会话与 CSRF ⇒ 调用者控制着这个新会话。此时把
//! `session_token_hash` 换成新会话的摘要，只是让派生状态追上事实。
//!
//! 反过来，「已绑定就永久拒绝重绑」既不更安全也会制造死锁：
//!
//! - 不更安全：拿到泄露 `request_id` 的攻击者没有 holder Cookie，第一道
//!   就被拒；有 holder Cookie 意味着他就是那个浏览器，重绑给不了他任何
//!   凭本来拿不到的东西。
//! - 会死锁：会话过期后浏览器换新会话，`request_id` 仍在 URL 里，旧绑定
//!   永远匹配不上，`bind` 恒定失败，前端跟着 401 反复跳登录页（#270）。
//!
//! 「同一浏览器换账号后重绑」是同一条规则的自然结果，也是用户预期的
//! 「使用其他辰星通行证」流程：授权码在最终 `decide` 时按当时持有的会话
//! 签发，绑到谁就是谁批准的。
//!
//! # 原子性
//!
//! 重绑走 `replace_if_matches` 的 CAS：以读到的 `request_id` + `cas_revision`
//! 为期望身份，避免与并发的 `bind` / `decide` 互相覆盖。CAS 失败时重新读取
//! 重试，因为失败只说明「身份变了」，可能是并发绑定（重试后收敛）也可能是
//! 请求已被消费（重试后按过期处理）。重试次数有上限，避免在持续竞争下无限打转。

use super::{consent::PendingAuthorization, request_store::AuthorizationRequestStore};
use crate::sessions::domain::session_token_hash;

/// CAS 重试上限。并发绑定只可能来自同一个浏览器的重复提交，两三次足以收敛；
/// 超过上限说明存在持续竞争，如实报告冲突而不是无限重试。
const MAX_BIND_ATTEMPTS: usize = 3;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PendingRequestBindingError {
    /// pending 请求不存在或已被消费。
    Expired,
    /// holder Cookie 缺失、不匹配，或 pending 记录没有 holder 摘要（旧记录）。
    HolderInvalid,
    /// 持续的并发修改让 CAS 无法收敛。调用方应让用户重试而不是重新发起授权。
    Contended,
    /// 存储层故障。
    Storage,
}

/// 绑定结果。区分两种成功，供调用方决定是否留审计痕迹。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PendingRequestBinding {
    /// 已绑定到同一会话，载荷未改动（幂等重试）。
    Unchanged,
    /// 从未绑定状态首次绑定。
    Bound,
    /// 从另一个会话摘要重绑到当前会话（会话过期重登或切换账号）。
    Rebound,
}

/// 把 `request_id` 指向的 pending 请求绑定到 `session_token` 所属的会话。
///
/// 调用方必须**先**确认 `session_token` 对应的会话有效，并且（浏览器入口）
/// 已通过 CSRF 校验。本函数只负责 holder 校验与原子重绑，不做会话校验。
///
/// `holder_hash` 是调用方从 holder Cookie 算出的摘要，`None` 表示没带 Cookie。
pub(crate) async fn bind_pending_request(
    store: &AuthorizationRequestStore,
    request_id: &str,
    session_token: &str,
    holder_hash: Option<&str>,
    issuer_generation: i64,
) -> Result<PendingRequestBinding, PendingRequestBindingError> {
    let session_hash = session_token_hash(session_token);
    for _ in 0..MAX_BIND_ATTEMPTS {
        let Some(pending) = load_pending(store, request_id).await? else {
            return Err(PendingRequestBindingError::Expired);
        };
        if !pending.is_bound_to_issuer_generation(issuer_generation) {
            discard_issuer_mismatched_pending(store, request_id, &pending).await?;
            return Err(PendingRequestBindingError::Expired);
        }
        // holder 校验先于一切：包括幂等重试在内的每一次调用都必须证明自己
        // 就是发起授权的那个浏览器。
        if !holder_matches(holder_hash, &pending) {
            return Err(PendingRequestBindingError::HolderInvalid);
        }
        let outcome = match pending.session_token_hash.as_deref() {
            Some(existing) if existing == session_hash => {
                return Ok(PendingRequestBinding::Unchanged);
            }
            None => PendingRequestBinding::Bound,
            Some(_) => PendingRequestBinding::Rebound,
        };
        let mut replacement = pending.clone();
        replacement.session_token_hash = Some(session_hash.clone());
        match store
            .replace_if_matches(request_id, &pending, &replacement)
            .await
        {
            Ok(true) => return Ok(outcome),
            // CAS 失败：载荷在读取与写入之间变了。这里什么都不做，下一轮重新读取
            // 即可判断是并发绑定（收敛为 Unchanged 或再次重绑）还是已被消费（Expired）。
            Ok(false) => {}
            Err(error_value) => {
                tracing::error!(
                    error = %error_value,
                    "failed to bind pending authorization request to session"
                );
                return Err(PendingRequestBindingError::Storage);
            }
        }
    }
    Err(PendingRequestBindingError::Contended)
}

/// Consume a pending request that was created under a different issuer runtime
/// generation. A CAS failure is still treated as expired by the caller: the
/// next continuation will apply the same generation check to the current value.
pub(crate) async fn discard_issuer_mismatched_pending(
    store: &AuthorizationRequestStore,
    request_id: &str,
    pending: &PendingAuthorization,
) -> Result<(), PendingRequestBindingError> {
    store
        .take_if_matches(request_id, pending)
        .await
        .map(|_| ())
        .map_err(|error_value| {
            tracing::error!(
                error = %error_value,
                "failed to discard issuer-mismatched OAuth authorization request"
            );
            PendingRequestBindingError::Storage
        })
}

async fn load_pending(
    store: &AuthorizationRequestStore,
    request_id: &str,
) -> Result<Option<PendingAuthorization>, PendingRequestBindingError> {
    let pending = store.find(request_id).await.map_err(|error_value| {
        tracing::error!(
            error = %error_value,
            "failed to load pending authorization request for binding"
        );
        PendingRequestBindingError::Storage
    })?;
    // 载荷里的 request_id 与查询键不一致意味着存储被污染，按不存在处理。
    Ok(pending.filter(|pending| pending.request_id == request_id))
}

/// holder 校验（#115）：Cookie 摘要必须与 pending 记录中的摘要一致。
///
/// 任一侧缺失都拒绝（fail-secure）。pending 侧缺失意味着升级前创建的旧记录，
/// 拒绝是有意为之：不留「无 holder 即放行」的绕过窗口，用户重新发起授权即可。
fn holder_matches(holder_hash: Option<&str>, pending: &PendingAuthorization) -> bool {
    match (holder_hash, pending.holder_hash.as_deref()) {
        (Some(presented), Some(stored)) => presented == stored,
        _ => false,
    }
}
