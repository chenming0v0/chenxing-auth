//! 兑换端点的输入体、候选资源服务选择与无状态辅助函数。

use std::fmt;

use axum::http::{HeaderMap, header::AUTHORIZATION};
use serde::Deserialize;

use crate::resource_services::scopes::ProviderScope;
use crate::resource_services::types::BindingRow;

pub(super) const SESSION_TOKEN_LIFETIME_SECONDS: u64 = 300;
pub(super) const MAX_DEVICE_ID_BYTES: usize = 255;
pub(super) const MAX_DEVICE_INFO_BYTES: usize = 1024;

/// 按 subject 的兑换限流：10 次 / 60 秒。
///
/// 正常一键登录在一分钟内远低于 10 次；该上限只用来阻挡单个账号被脚本化地
/// 反复兑换会话令牌。窗口与阈值是端点语义，不引入新的可配置项。
pub(super) const EXCHANGE_RATE_LIMIT: u32 = 10;
pub(super) const EXCHANGE_RATE_WINDOW_MS: i64 = 60_000;

pub(super) const BAD_REQUEST_MESSAGE: &str = "the exchange request is invalid";
pub(super) const INVALID_TOKEN_MESSAGE: &str = "the Chenxing access token is invalid";
pub(super) const UNAVAILABLE_MESSAGE: &str = "authorization state is unavailable";
pub(super) const NOT_LINKED_MESSAGE: &str = "the user has no linked account";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeInput {
    /// 审计用设备标识；必填、非空、≤255 字节，不做设备判定。
    pub device_id: String,
    /// 审计用设备描述；可选、≤1024 字节，明文永不落库。
    #[serde(default)]
    pub device_info: Option<String>,
    /// 资源服务 slug；令牌覆盖多个资源服务 scope 时必填。
    #[serde(default)]
    pub provider: Option<String>,
}

impl fmt::Debug for ExchangeInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeInput")
            .field("device_id", &self.device_id)
            .field(
                "device_info",
                &self.device_info.as_ref().map(|_| "<redacted>"),
            )
            .field("provider", &self.provider)
            .finish()
    }
}

/// 候选资源服务的选择结果。
pub(super) enum Selection {
    Chosen(ProviderScope),
    /// 令牌 scope 不覆盖任何资源服务，或指定的 `provider` 不在候选内。
    NoScope,
    /// 多个候选且请求体未指明 `provider`。
    Ambiguous,
}

/// 纯函数：从 grant gate 收窄后的 scope 里挑出目标资源服务。
pub(super) fn select_provider(
    providers: Vec<ProviderScope>,
    scopes: &[String],
    requested_slug: Option<&str>,
) -> Selection {
    let mut candidates = providers
        .into_iter()
        .filter(|provider| scopes.iter().any(|scope| scope == &provider.scope))
        .collect::<Vec<_>>();
    if let Some(slug) = requested_slug {
        return match candidates
            .into_iter()
            .find(|provider| provider.slug == slug)
        {
            Some(provider) => Selection::Chosen(provider),
            None => Selection::NoScope,
        };
    }
    match candidates.len() {
        0 => Selection::NoScope,
        1 => Selection::Chosen(candidates.remove(0)),
        _ => Selection::Ambiguous,
    }
}

/// 快照里的账号状态。只认提供方协议定义的 `active` / `disabled`，其余按未绑定处理。
pub(super) fn snapshot_status(binding: &BindingRow) -> Option<&str> {
    binding
        .snapshot_json
        .get("status")
        .and_then(serde_json::Value::as_str)
}

/// 从 `Authorization` 头提取 Bearer 令牌。本端点不使用入站 interop 凭据，
/// 认证材料只有用户自己的 Access Token。
pub(super) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token)
        .filter(|token| !token.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_services::types::ScopeAccess;

    fn provider(slug: &str, scope: &str) -> ProviderScope {
        ProviderScope {
            provider_id: uuid::Uuid::new_v4(),
            scope: scope.to_owned(),
            slug: slug.to_owned(),
            display_name: slug.to_owned(),
            description: String::new(),
            access: ScopeAccess::Public,
            allowed_client_ids: Vec::new(),
        }
    }

    fn scopes(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn single_matching_provider_is_chosen_without_a_slug() {
        let providers = vec![provider("a", "a:access"), provider("b", "b:access")];
        match select_provider(providers, &scopes(&["openid", "b:access"]), None) {
            Selection::Chosen(chosen) => assert_eq!(chosen.slug, "b"),
            _ => panic!("expected a single candidate"),
        }
    }

    #[test]
    fn multiple_candidates_require_an_explicit_slug() {
        let providers = || vec![provider("a", "a:access"), provider("b", "b:access")];
        let granted = scopes(&["a:access", "b:access"]);
        assert!(matches!(
            select_provider(providers(), &granted, None),
            Selection::Ambiguous
        ));
        assert!(matches!(
            select_provider(providers(), &granted, Some("a")),
            Selection::Chosen(chosen) if chosen.slug == "a"
        ));
        assert!(matches!(
            select_provider(providers(), &granted, Some("c")),
            Selection::NoScope
        ));
    }

    #[test]
    fn no_overlap_means_no_scope() {
        let providers = vec![provider("a", "a:access")];
        assert!(matches!(
            select_provider(providers, &scopes(&["openid"]), None),
            Selection::NoScope
        ));
    }
}
