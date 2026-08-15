//! 已签发凭据在**兑换时刻**的授权准入闸门。
//!
//! `/oauth/authorize` 校验的是「请求 scope ⊆ Client 注册 scope ∩ 平台
//! allowlist」，但那是一次性判定。授权码（约 5 分钟）、Refresh Token（滑动
//! 30 天 / 绝对 180 天）和 Access Token（默认 3600 秒）的寿命都远长于那一次
//! 请求，期间 Client 可能被禁用、注册 scope 可能被缩减、用户可能撤销授权。
//! 兑换路径若只相信凭据自己携带的 scope，配置意图和用户意图就都活不过签发
//! 时刻。
//!
//! 三条兑换路径此前各自维护自己的一部分判定，缺口互不相同：
//!
//! - 授权码兑换完全没有同意门禁，撤销应用后仍能换出令牌（Issue #417）。
//! - Refresh 与 UserInfo 只查 consent，不看 Client 当前注册 scope，管理员
//!   缩减 scope 后旧授权继续按旧集合续签（Issue #421）。
//! - UserInfo 不看 Client 状态，禁用客户端后 Access Token 仍能拉用户信息
//!   （Issue #420）。
//!
//! 与其在三处分别补三个 if，这里把判定收敛成单一入口：**Client 当前可用 →
//! 同意未撤销 → scope 收窄到当前注册集合 ∩ 平台 allowlist → 同意仍覆盖收窄
//! 后的集合**。任一环节不通过一律 fail-closed，存储故障与授权失效严格区分，
//! 后者才允许销毁凭据。
//!
//! 返回值是**收窄后的 scope 集合**而不是布尔判定：调用方必须用它替换凭据里
//! 的原始集合去签发下一枚令牌，否则「不再注册的 scope 不得续签」只是拒绝了
//! 整个请求，而不是收窄权限。

use crate::{state::AppState, users::domain::UserId};

/// 闸门的拒绝原因。
///
/// 两个变体的处置完全不同，不能压缩成 `Option`：`Denied` 是授权事实（凭据
/// 应当失效），`Unavailable` 是基础设施故障。把故障当成失效会让一次 Redis
/// 抖动烧掉用户的有效授权；把失效当成故障则让撤销失效。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantGateError {
    /// 授权已不成立。`&'static str` 是审计原因码，可安全进日志。
    Denied(&'static str),
    /// 存储暂时不可用，本次请求不能据此判定授权状态。
    Unavailable(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveGrant {
    pub(crate) scopes: Vec<String>,
    pub(crate) consent_state_version: i64,
}

impl GrantGateError {
    /// 审计与日志用的原因码；不含用户输入，也不含凭据材料。
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Denied(reason) | Self::Unavailable(reason) => reason,
        }
    }
}

/// 计算一份已签发授权在当前时刻仍然有效的 scope 集合。
///
/// `granted` 是凭据签发时记录的集合（授权码的 `scopes`、Refresh Token 的
/// `scopes`、Access Token 的 `scope` claim）。返回值保持 `granted` 的顺序，
/// 只做过滤，不做扩展——闸门永远不会给出比签发时更多的权限。
///
/// 判定顺序按「成本递增、且尽早拒绝」排列：先做一次 Redis 命中率很高的撤销
/// 检查，再回 PostgreSQL 读 Client 注册信息与同意行。
pub(crate) async fn effective_grant_scopes(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    granted: &[String],
) -> Result<EffectiveGrant, GrantGateError> {
    let Ok(subject) = user_id.parse::<UserId>() else {
        return Err(GrantGateError::Denied("invalid_subject"));
    };

    // 用户撤销授权（「断开应用」）的权威事实在 PostgreSQL，Redis 只是缓存；
    // 缓存只能拒绝请求，不能替数据库放行请求（见 `consents::repository`）。
    match state
        .revocations
        .is_consent_revoked(user_id, client_id)
        .await
    {
        Ok(true) => return Err(GrantGateError::Denied("consent_revoked")),
        Ok(false) => {}
        Err(store_error) => {
            tracing::error!(error = %store_error, "failed to check OAuth consent revocation");
            return Err(GrantGateError::Unavailable(
                "consent_revocation_check_failed",
            ));
        }
    }

    // `find_registered` 对非 active 状态返回 `None`：禁用 Client 与不存在的
    // Client 在兑换路径上处置相同，都不得继续换取或使用令牌（Issue #420）。
    let client = match state.clients.find_registered(client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return Err(GrantGateError::Denied("client_unavailable")),
        Err(service_error) => {
            tracing::error!(error = %service_error, "failed to load OAuth client for grant gate");
            return Err(GrantGateError::Unavailable("client_lookup_failed"));
        }
    };

    // 收窄而不是整体拒绝：管理员从 Client 上去掉 `email` 之后，既有授权应当
    // 继续以剩余 scope 工作，而不是让所有客户端一起失效。平台 allowlist 同时
    // 参与判定，因为它是 scope 的最终上界（`OAUTH_CLIENT_ALLOWED_SCOPES`）。
    let allowlist = &state.config.client_registration_limits.allowed_scopes;
    let effective = granted
        .iter()
        .filter(|scope| {
            client.scopes.iter().any(|registered| registered == *scope)
                && allowlist.iter().any(|allowed| allowed == *scope)
        })
        .cloned()
        .collect::<Vec<_>>();
    if effective.is_empty() {
        // 一个零权限的 Access Token 没有任何用途，签发它只会让调用方以为
        // 兑换成功。全部 scope 都已失效时按授权失效处理。
        return Err(GrantGateError::Denied("scopes_no_longer_registered"));
    }

    // 同意行是用户意图的权威记录：二次同意可能只授予了子集，撤销后重新授权
    // 也可能缩小了范围。收窄后的集合仍必须被它覆盖。
    match state
        .consents
        .has_scopes(subject, client_id, &effective)
        .await
    {
        Ok(true) => {
            let state = state
                .consents
                .consent_state(subject, client_id)
                .await
                .map_err(|error| {
                    tracing::error!(error = %error, "failed to load OAuth consent state version");
                    GrantGateError::Unavailable("consent_state_version_check_failed")
                })?;
            let Some(state) = state else {
                return Err(GrantGateError::Denied("consent_missing_scopes"));
            };
            if state.revoked {
                return Err(GrantGateError::Denied("consent_revoked"));
            }
            Ok(EffectiveGrant {
                scopes: effective,
                consent_state_version: state.version,
            })
        }
        Ok(false) => Err(GrantGateError::Denied("consent_missing_scopes")),
        Err(database_error) => {
            tracing::error!(error = %database_error, "failed to check OAuth consent scopes");
            Err(GrantGateError::Unavailable("consent_scope_check_failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GrantGateError;

    /// 原因码要能直接进审计元数据：两个变体都必须给出稳定字符串。
    #[test]
    fn reason_codes_are_available_for_both_dispositions() {
        assert_eq!(
            GrantGateError::Denied("consent_revoked").reason(),
            "consent_revoked"
        );
        assert_eq!(
            GrantGateError::Unavailable("client_lookup_failed").reason(),
            "client_lookup_failed"
        );
    }

    /// 拒绝与故障必须可区分：调用方据此决定是销毁凭据还是回 503 让客户端重试。
    #[test]
    fn denial_and_unavailability_are_distinct_dispositions() {
        assert_ne!(
            GrantGateError::Denied("consent_revoked"),
            GrantGateError::Unavailable("consent_revoked")
        );
    }
}
