//! 用户安全日志的公开视图（Issue #307 / #308）。
//!
//! 这些结构是用户可见的显式白名单：不含 actor、resource_id 原文或 metadata 原文。
//! OAuth Client 信息只由 repository 从已知的 Client 资源类型提取，不能把任意审计
//! 资源标识误当成公开字段。`category` / `severity` 由 [`super::classify`] 单点映射，
//! 列表与详情共用。

use serde::Serialize;
use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::{SecurityEventCategory, SecurityEventSeverity};

/// 用户可见的审计事件摘要。
#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub id: i64,
    pub action: String,
    pub category: SecurityEventCategory,
    pub severity: SecurityEventSeverity,
    pub resource_type: String,
    pub client_id: Option<String>,
    pub client_name: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// 单个安全事件的详情（Issue #308）。
///
/// `ip` / `user_agent` 只从 metadata 白名单提取（见 [`security_event_request_context`]），
/// 绝不透出 metadata 原文。`ip_location` 与 `ray_id` 尚无数据来源（离线归属地库 /
/// 请求关联 ID），恒为 null，保留字段是为了让前端按固定契约处理（提案约定可空）。
#[derive(Debug, Clone, Serialize)]
pub struct SecurityEventDetail {
    pub id: i64,
    pub action: String,
    pub category: SecurityEventCategory,
    pub severity: SecurityEventSeverity,
    pub resource_type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub ip: Option<String>,
    pub ip_location: Option<String>,
    pub user_agent: Option<String>,
    pub ray_id: Option<String>,
    /// 仅 OAuth 相关事件填充；Client 已被删除时为 null，前端降级展示。
    pub client: Option<SecurityEventClient>,
}

/// 详情接口中 OAuth Client 的公开摘要，只来自 `oauth_clients` 表自身列。
#[derive(Debug, Clone, Serialize)]
pub struct SecurityEventClient {
    pub client_id: String,
    pub client_name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub status: String,
}

/// 从事件 metadata 白名单提取用户可见的请求上下文（Issue #308）。
///
/// metadata 在写入时已经过整体脱敏（[`super::redact_metadata`]），这里仍然只允许
/// `source_ip` 与 `user_agent` 两个键进入详情接口，并且只读字符串值。新增白名单
/// 键必须同时评估其敏感性；返回的元组是 (ip, user_agent)。
pub(crate) fn security_event_request_context(
    metadata: &Map<String, Value>,
) -> (Option<String>, Option<String>) {
    let ip = metadata
        .get("source_ip")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let user_agent = metadata
        .get("user_agent")
        .and_then(Value::as_str)
        .map(str::to_owned);
    (ip, user_agent)
}

/// 把请求上下文（源 IP、User-Agent）写进审计 metadata（Issue #308）。
///
/// 只有非空值才写入，避免 metadata 里出现无意义的 null 键。调用方传入的
/// `source_ip` 必须已经过 [`crate::api::source_ip`] 的可信代理解析。
pub(crate) fn with_request_context(
    mut metadata: Value,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) -> Value {
    if let Some(source_ip) = source_ip.filter(|value| !value.is_empty()) {
        metadata["source_ip"] = Value::String(source_ip.to_owned());
    }
    if let Some(user_agent) = user_agent.filter(|value| !value.is_empty()) {
        metadata["user_agent"] = Value::String(user_agent.to_owned());
    }
    metadata
}
