//! CLtermux HTTP 契约的 serde 类型。
//!
//! 这些类型只描述线上协议形状；应用层语义在 [`super::types`]。时间字段统一
//! 使用 `time::OffsetDateTime` + `time::serde::rfc3339`，与仓库现有 admin
//! handlers 的序列化惯例一致（RFC 3339 UTC 字符串）。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// 出站 verify 请求体。手写 Debug 脱敏：契约类型可能被日志间接打印，
/// 绝不能输出原值。
#[derive(Serialize, PartialEq, Eq)]
pub struct VerifyRequest {
    pub public_key: String,
    pub private_key: String,
}

impl std::fmt::Debug for VerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyRequest")
            .field("public_key", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// 供应商返回的账号快照 DTO。结构校验在 [`super::validation`] 完成；
/// serde 解析前的 128 KiB 原始大小检查由调用方负责。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountSnapshotDto {
    pub schema_version: String,
    pub uid: String,
    pub subject: String,
    pub display: DisplayDto,
    pub status: String,
    pub subscription: SubscriptionDto,
    pub device: DeviceDto,
    #[serde(default)]
    pub extensions: Vec<ExtensionBlockDto>,
    #[serde(with = "time::serde::rfc3339")]
    pub fetched_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisplayDto {
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionDto {
    pub is_subscribed: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// 供应商侧的剩余天数。`remaining_days = -1` 哨兵是旧
    /// `chenxing.subscription` 运行时扩展的约定，与本快照无关；
    /// 这里是普通非负整数，负值即校验失败。
    pub remaining_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceDto {
    pub status: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_seen_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtensionBlockDto {
    pub namespace: String,
    pub version: String,
    #[serde(default)]
    pub fields: Vec<ExtensionFieldDto>,
    #[serde(with = "time::serde::rfc3339")]
    pub fetched_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtensionFieldDto {
    pub key: String,
    pub label: String,
    /// 字段类型标签：text/number/boolean/status/datetime/duration_days/url。
    #[serde(rename = "type")]
    pub r#type: String,
    /// 原始 JSON 值；类型语义校验在 validation 层完成。
    pub value: serde_json::Value,
}

/// 辰星→CLtermux 的 resolve 响应（出站解析结果）。
///
/// 时间字段沿用仓库惯例：RFC 3339 UTC 字符串经 `time::serde::rfc3339`。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolveResponse {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub scope: String,
    pub provider: String,
    pub uid: String,
    pub binding_id: String,
    pub binding_version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub resolved_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub valid_until: OffsetDateTime,
}

/// 供应商统一错误体（出站解析用）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationErrorBody {
    pub error: IntegrationErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationErrorDetail {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub request_id: String,
}
