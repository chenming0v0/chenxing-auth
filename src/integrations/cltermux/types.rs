//! CLtermux 绑定用例的领域类型。
//!
//! 这些类型是应用层内部语义，不直接暴露 HTTP 契约；HTTP 契约类型在
//! [`super::contract`]。凭据类型实现 Drop 静默、Debug 脱敏，且不 derive
//! Clone——凭据不该被复制扩散。

use serde::{Deserialize, Serialize};

/// 一次绑定/刷新请求携带的卡密凭据对。
///
/// 只在请求生命周期内存在：adapter 用它调用供应商 verify，请求结束即丢弃。
/// 绝不序列化到存储、日志或队列；Debug 输出脱敏，Drop 静默（不打印内容）。
pub struct CredentialBundle {
    pub public_key: String,
    pub private_key: String,
}

impl std::fmt::Debug for CredentialBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialBundle")
            .field("public_key", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl Drop for CredentialBundle {
    fn drop(&mut self) {
        // 静默丢弃：任何日志输出都会把凭据带进聚合管道。
    }
}

/// 应用层已校验的展示快照，对应 `linked_accounts` 表列。
///
/// 只有通过 [`super::validation::validate_snapshot`] 的快照才会进入这里；
/// 校验失败的供应商响应不覆盖旧快照。
#[derive(Debug, Clone, PartialEq)]
pub struct LinkedAccountSnapshot {
    pub account_status: AccountStatus,
    pub display: SnapshotDisplay,
    pub subscription: SnapshotSubscription,
    pub device: SnapshotDevice,
    pub extensions: serde_json::Value,
    pub fetched_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDisplay {
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotSubscription {
    pub is_subscribed: bool,
    pub expires_at: Option<time::OffsetDateTime>,
    pub remaining_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDevice {
    pub status: DeviceStatus,
    pub last_seen_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Disabled,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Unbound,
    Bound,
    Unknown,
}

/// 绑定用例结果。
#[derive(Debug, Clone, PartialEq)]
pub enum BindOutcome {
    Bound {
        binding_id: String,
        snapshot: LinkedAccountSnapshot,
    },
    /// 供应商确认凭据无效；旧快照与绑定关系保持不变。
    Rejected(IntegrationError),
}

/// 刷新（重新同步）用例结果。
#[derive(Debug, Clone, PartialEq)]
pub enum RefreshOutcome {
    Refreshed {
        snapshot: LinkedAccountSnapshot,
    },
    /// 供应商响应不合法：不覆盖旧快照，保留上次成功数据。
    KeptStale(IntegrationError),
}

/// 集成错误。消息是稳定的非敏感英文语义 code，绝不回显凭据或供应商原始响应。
///
/// 括号内是建议的对外 HTTP 状态映射（由 handlers lane 决定最终响应）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrationError {
    /// 卡密凭据无效或已被供应商拒绝（422）。
    #[error("credentials are invalid")]
    InvalidCredential,
    /// 供应商侧账号被禁用（403）。
    #[error("account is disabled")]
    AccountDisabled,
    /// 供应商侧账号不存在（404）。
    #[error("account was not found")]
    AccountNotFound,
    /// 该账号或 uid 已绑定（409）。
    #[error("account is already linked")]
    AlreadyLinked,
    /// 供应商返回了不符合契约的响应（502）。
    #[error("provider returned an invalid response")]
    ProviderInvalidResponse,
    /// 出站 Bearer 被供应商拒绝（502）。
    #[error("provider authentication failed")]
    ProviderAuthFailed,
    /// 供应商不可达或非 2xx（503）。
    #[error("provider is unavailable")]
    ProviderUnavailable,
    /// 出站请求超时（504）。
    #[error("provider request timed out")]
    ProviderTimeout,
    /// 供应商限流（429）。
    #[error("provider request is rate limited")]
    RateLimited { retry_after_secs: u32 },
    /// CLtermux 集成未配置（禁用状态）。
    #[error("provider integration is not configured")]
    NotConfigured,
}

impl AccountStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
        }
    }
}

impl DeviceStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unbound => "unbound",
            Self::Bound => "bound",
            Self::Unknown => "unknown",
        }
    }
}

impl IntegrationError {
    /// Stable public error code; no provider response or credential is included.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidCredential => "credential_invalid",
            Self::AccountDisabled => "account_disabled",
            Self::AccountNotFound => "account_not_found",
            Self::AlreadyLinked => "account_already_linked",
            Self::ProviderInvalidResponse => "provider_invalid_response",
            Self::ProviderAuthFailed => "provider_auth_failed",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ProviderTimeout => "provider_timeout",
            Self::RateLimited { .. } => "rate_limited",
            Self::NotConfigured => "provider_capability_unsupported",
        }
    }

    pub fn retry_after_secs(&self) -> Option<u32> {
        match self {
            Self::RateLimited { retry_after_secs } => Some(*retry_after_secs),
            _ => None,
        }
    }
}

/// 供 handlers lane 做响应映射的 serde 视图（可选使用）。
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationErrorBody {
    pub error: IntegrationErrorDetail,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationErrorDetail {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub request_id: String,
}
