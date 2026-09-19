//! 动态 scope 目录。
//!
//! 基础 scope（`openid` / `profile` / `email` 等）来自配置的
//! `client_registration_limits.allowed_scopes`；资源服务声明的 scope 来自
//! 已启用的 `resource_service_providers` 行。某个应用能申请的完整 allowlist =
//! 基础 scope + 所有 `public` 服务 scope + 该应用被列入 `allowed_client_ids`
//! 的 `restricted` 服务 scope。
//!
//! 匿名 Discovery 的 `scopes_supported` 只有基础 scope + 已启用 public 服务
//! scope；restricted 不得出现在公开清单里。已登记客户端通过
//! [`filter_scopes`] / [`client_scope_allowlist`] 按 `allowed_client_ids` 拿到
//! 自己的 restricted。
//!
//! 查库失败时调用方一律退回基础 scope：资源 scope 对外 fail closed。

use serde::Serialize;
use uuid::Uuid;

use super::ResourceServiceService;
use super::service_error::ServiceError;
use super::types::{ProviderRow, ScopeAccess};
use crate::clients::service::ClientService;
use crate::state::AppState;

/// 已启用资源服务声明的 scope 及其开放范围。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderScope {
    pub provider_id: Uuid,
    pub scope: String,
    pub slug: String,
    pub display_name: String,
    pub description: String,
    pub access: ScopeAccess,
    pub allowed_client_ids: Vec<String>,
}

impl ProviderScope {
    fn from_row(row: &ProviderRow) -> Self {
        Self {
            provider_id: row.id,
            scope: row.scope.clone(),
            slug: row.slug.clone(),
            display_name: row.display_name.clone(),
            description: row.scope_description.clone(),
            access: row.scope_access,
            allowed_client_ids: row.allowed_client_ids.clone(),
        }
    }

    /// `client_id` 为 `None` 表示应用尚未注册：只有 public scope 可见。
    pub fn visible_to(&self, client_id: Option<&str>) -> bool {
        match self.access {
            ScopeAccess::Public => true,
            ScopeAccess::Restricted => client_id
                .is_some_and(|client| self.allowed_client_ids.iter().any(|id| id == client)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSource {
    Base,
    ResourceService,
}

/// `GET /api/v1/auth/oauth-scopes` 的单个条目；字段形状与前端类型一一对应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeCatalogItem {
    pub scope: String,
    pub title: String,
    pub description: String,
    pub source: ScopeSource,
    pub access: Option<ScopeAccess>,
    pub provider_slug: Option<String>,
}

impl ScopeCatalogItem {
    fn base(scope: &str) -> Self {
        let (title, description) = base_scope_copy(scope);
        Self {
            scope: scope.to_owned(),
            title: title.to_owned(),
            description: description.to_owned(),
            source: ScopeSource::Base,
            access: None,
            provider_slug: None,
        }
    }

    fn resource_service(provider: &ProviderScope) -> Self {
        Self {
            scope: provider.scope.clone(),
            title: provider.display_name.clone(),
            description: provider.description.clone(),
            source: ScopeSource::ResourceService,
            access: Some(provider.access),
            provider_slug: Some(provider.slug.clone()),
        }
    }
}

/// 基础 scope 的固定文案；未知的基础 scope 用 scope 本身作标题。
pub fn base_scope_copy(scope: &str) -> (&str, &str) {
    match scope {
        "openid" => ("身份标识", "获取你的唯一辰星 ID，用于识别账户身份"),
        "profile" => ("基本资料", "查看你的昵称、头像与公开个人信息"),
        "email" => ("电子邮箱", "读取与你账号关联的邮箱地址"),
        "offline_access" => ("离线访问", "在你离线时刷新访问令牌"),
        other => (other, "应用请求的额外权限范围"),
    }
}

/// 纯函数：基础 scope 在前（保持配置顺序），服务 scope 按 slug 排序追加，去重。
pub fn filter_scopes(
    base: &[String],
    providers: &[ProviderScope],
    client_id: Option<&str>,
) -> Vec<String> {
    merge_scopes(
        base,
        providers
            .iter()
            .filter(|provider| provider.visible_to(client_id)),
    )
}

fn merge_scopes<'a>(
    base: &[String],
    providers: impl Iterator<Item = &'a ProviderScope>,
) -> Vec<String> {
    let mut visible = providers.collect::<Vec<_>>();
    visible.sort_by(|left, right| left.slug.cmp(&right.slug));
    let mut scopes: Vec<String> = Vec::with_capacity(base.len() + visible.len());
    for scope in base
        .iter()
        .cloned()
        .chain(visible.into_iter().map(|provider| provider.scope.clone()))
    {
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    scopes
}

impl ResourceServiceService {
    /// 已启用资源服务的 scope 声明。每次查库，不缓存。
    pub async fn provider_scopes(&self) -> Result<Vec<ProviderScope>, ServiceError> {
        let rows = self.store.list_enabled_providers().await?;
        Ok(rows.iter().map(ProviderScope::from_row).collect())
    }

    /// 某个应用可申请的完整 allowlist。
    pub async fn allowed_scopes_for_client(
        &self,
        base: &[String],
        client_id: Option<&str>,
    ) -> Result<Vec<String>, ServiceError> {
        let providers = self.provider_scopes().await?;
        Ok(filter_scopes(base, &providers, client_id))
    }

    /// Discovery 用：基础 scope + 已启用 public 服务 scope。
    ///
    /// 匿名端点不得暴露 restricted 服务 scope；那些只通过
    /// [`Self::allowed_scopes_for_client`] 发给已列入 `allowed_client_ids` 的应用。
    pub async fn all_enabled_scopes(&self, base: &[String]) -> Result<Vec<String>, ServiceError> {
        let providers = self.provider_scopes().await?;
        Ok(filter_scopes(base, &providers, None))
    }

    /// 权限清单目录：基础项 + 对该应用可见的服务项。
    pub async fn scope_catalog(
        &self,
        base: &[String],
        client_id: Option<&str>,
    ) -> Result<Vec<ScopeCatalogItem>, ServiceError> {
        let mut providers = self.provider_scopes().await?;
        providers.retain(|provider| provider.visible_to(client_id));
        providers.sort_by(|left, right| left.slug.cmp(&right.slug));
        let mut items = base
            .iter()
            .map(String::as_str)
            .map(ScopeCatalogItem::base)
            .collect::<Vec<_>>();
        for provider in &providers {
            if items.iter().any(|item| item.scope == provider.scope) {
                continue;
            }
            items.push(ScopeCatalogItem::resource_service(provider));
        }
        Ok(items)
    }
}

/// 运行时 allowlist：查库失败退回基础 scope（资源 scope fail closed）。
pub async fn client_scope_allowlist(state: &AppState, client_id: Option<&str>) -> Vec<String> {
    let base = &state.config.client_registration_limits.allowed_scopes;
    match state
        .resource_services
        .allowed_scopes_for_client(base, client_id)
        .await
    {
        Ok(scopes) => scopes,
        Err(error) => {
            tracing::warn!(
                error = %error,
                client_id = client_id.unwrap_or(""),
                "resource service scope lookup failed; falling back to base scopes"
            );
            base.clone()
        }
    }
}

/// 带上该应用 allowlist 的 `ClientService` 副本，供注册 / 更新校验使用。
pub async fn scoped_client_service(state: &AppState, client_id: Option<&str>) -> ClientService {
    let allowlist = client_scope_allowlist(state, client_id).await;
    state.clients.with_scope_allowlist(allowlist)
}

#[cfg(test)]
mod tests {
    use super::super::types::ScopeAccess;
    use super::*;

    fn base() -> Vec<String> {
        ["openid", "profile", "email"]
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect()
    }

    fn provider(slug: &str, scope: &str, access: ScopeAccess, clients: &[&str]) -> ProviderScope {
        ProviderScope {
            provider_id: Uuid::new_v4(),
            scope: scope.to_owned(),
            slug: slug.to_owned(),
            display_name: slug.to_uppercase(),
            description: format!("{slug} description"),
            access,
            allowed_client_ids: clients.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    /// `all_enabled_scopes` 走 `filter_scopes(..., None)`：公开清单含 public、不含 restricted。
    #[test]
    fn anonymous_discovery_keeps_public_and_omits_restricted() {
        let providers = vec![
            provider("public-svc", "public-svc:access", ScopeAccess::Public, &[]),
            provider(
                "secret-svc",
                "secret-svc:access",
                ScopeAccess::Restricted,
                &["cx_listed"],
            ),
        ];
        assert_eq!(
            filter_scopes(&base(), &providers, None),
            vec!["openid", "profile", "email", "public-svc:access"]
        );
        assert_eq!(
            filter_scopes(&base(), &providers, Some("cx_listed")),
            vec![
                "openid",
                "profile",
                "email",
                "public-svc:access",
                "secret-svc:access"
            ]
        );
    }
}
