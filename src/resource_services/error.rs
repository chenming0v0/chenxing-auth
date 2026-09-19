//! Account Provider v1 消费方错误类型。
//!
//! 面向调用方的错误一律**不携带原始值**：不包含 provider 返回的 `message`、
//! 凭据、令牌、URL 或解析到的地址。可检索上下文只保留静态字段名与错误类别，
//! 这样日志可以安全检索，同时不会把对方原始错误或本地方配置回显出去。

use std::fmt;
use std::time::Duration;
use thiserror::Error;

use super::transport::TransportError;

/// 快照 / 令牌包 / 请求体的严格校验错误。
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("account provider payload is not a JSON object")]
    NotAnObject,
    #[error("account provider payload is malformed JSON")]
    MalformedJson,
    #[error("account provider payload is missing required field `{0}`")]
    MissingRequired(&'static str),
    #[error("account provider field `{0}` has an unexpected type")]
    UnexpectedType(&'static str),
    #[error("account provider field `{0}` is invalid")]
    InvalidValue(&'static str),
    #[error("account provider protocol identifier is not `account-provider/v1`")]
    ProtocolMismatch,
    #[error("account provider issuer is not the configured origin")]
    IssuerMismatch,
    #[error("account provider snapshot issuer does not match its token bundle")]
    SnapshotIssuerMismatch,
    #[error("account provider snapshot uid does not match its token bundle")]
    SnapshotUidMismatch,
    #[error("account provider uid does not match the bound account")]
    UidMismatch,
    #[error("account provider client binding id does not match the request")]
    BindingMismatch,
    #[error("account provider grant id does not match the existing grant")]
    GrantMismatch,
    #[error("account provider grant expiry changed across a refresh")]
    GrantExpiryMismatch,
    #[error("account provider scope is not `account:read`")]
    ScopeMismatch,
    #[error("account provider token type is not `Bearer`")]
    TokenTypeMismatch,
    #[error("account provider access token is missing its protocol prefix")]
    InvalidAccessToken,
    #[error("account provider refresh token is missing its protocol prefix")]
    InvalidRefreshToken,
    #[error("account provider subscription kind is unknown")]
    UnknownSubscriptionKind,
    #[error("account provider subscription mixes fields from different variants")]
    SubscriptionFieldConflict,
    #[error("account provider snapshot has more than 64 fields")]
    TooManyFields,
    #[error("account provider snapshot has a duplicate field key")]
    DuplicateFieldKey,
    #[error("account provider field `{0}` exceeds its UTF-8 byte limit")]
    ByteLimitExceeded(&'static str),
    #[error("account provider refresh expiry exceeds the absolute grant expiry")]
    RefreshExpiryExceedsGrant,
    #[error("account provider client id is invalid")]
    InvalidClientId,
    #[error("account provider credentials are invalid")]
    InvalidCredentials,
    #[error("account provider request body exceeds the 8 KiB limit")]
    RequestTooLarge,
    #[error("account provider payload exceeds the 128 KiB limit")]
    PayloadTooLarge,
}

/// provider 错误信封里协议已知的错误码（protocol.md 第 10 节）。
///
/// 消费方只保留错误码与受限的 `Retry-After`；`message`、`request_id` 与对方
/// 原始包体一律丢弃，避免进入日志或响应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidAccessToken,
    InvalidRefreshToken,
    AccountDisabled,
    AccountNotFound,
    BindingConflict,
    IssuanceAlreadyCommitted,
    RefreshAlreadyCommitted,
    CredentialInvalid,
    RateLimited,
    ProviderUnavailable,
}

impl KnownErrorCode {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "invalid_request" => Self::InvalidRequest,
            "invalid_client" => Self::InvalidClient,
            "invalid_access_token" => Self::InvalidAccessToken,
            "invalid_refresh_token" => Self::InvalidRefreshToken,
            "account_disabled" => Self::AccountDisabled,
            "account_not_found" => Self::AccountNotFound,
            "binding_conflict" => Self::BindingConflict,
            "issuance_already_committed" => Self::IssuanceAlreadyCommitted,
            "refresh_already_committed" => Self::RefreshAlreadyCommitted,
            "credential_invalid" => Self::CredentialInvalid,
            "rate_limited" => Self::RateLimited,
            "provider_unavailable" => Self::ProviderUnavailable,
            _ => return None,
        })
    }

    /// 协议固定语义，不读取响应里的 `retryable` 字段。
    pub fn retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::ProviderUnavailable)
    }

    /// 协议 §10 里该错误码唯一对应的 HTTP 状态。
    ///
    /// 用于校验响应状态与错误码是否自洽：`502 + invalid_refresh_token` 这种组合
    /// 不能被当成本地凭据失效的证据，否则上层会销毁仍然有效的授权。
    pub fn expected_status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::InvalidClient | Self::InvalidAccessToken | Self::InvalidRefreshToken => 401,
            Self::AccountDisabled => 403,
            Self::AccountNotFound => 404,
            Self::BindingConflict
            | Self::IssuanceAlreadyCommitted
            | Self::RefreshAlreadyCommitted => 409,
            Self::CredentialInvalid => 422,
            Self::RateLimited => 429,
            Self::ProviderUnavailable => 503,
        }
    }

    /// 稳定字符串，用于结构化日志与错误分类；不是回显给用户的原始消息。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidAccessToken => "invalid_access_token",
            Self::InvalidRefreshToken => "invalid_refresh_token",
            Self::AccountDisabled => "account_disabled",
            Self::AccountNotFound => "account_not_found",
            Self::BindingConflict => "binding_conflict",
            Self::IssuanceAlreadyCommitted => "issuance_already_committed",
            Self::RefreshAlreadyCommitted => "refresh_already_committed",
            Self::CredentialInvalid => "credential_invalid",
            Self::RateLimited => "rate_limited",
            Self::ProviderUnavailable => "provider_unavailable",
        }
    }
}

/// provider 明确返回的已知失败。`retry_after` 已由传输层钳制上界。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderFailure {
    pub code: KnownErrorCode,
    pub retry_after: Option<Duration>,
}

impl ProviderFailure {
    pub fn retryable(&self) -> bool {
        self.code.retryable()
    }
}

impl fmt::Display for ProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

/// 消费方调用 provider 时的统一错误。
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("account provider transport failed")]
    Transport(#[from] TransportError),
    #[error("account provider returned error `{0}`")]
    Provider(ProviderFailure),
    #[error("account provider returned an unexpected status")]
    UnexpectedStatus(u16),
    #[error("account provider response is invalid")]
    InvalidResponse(#[from] ProtocolError),
    #[error("account provider response exceeds the 128 KiB limit")]
    ResponseTooLarge,
}

impl ClientError {
    pub fn provider_failure(&self) -> Option<ProviderFailure> {
        match self {
            Self::Provider(failure) => Some(*failure),
            _ => None,
        }
    }
}
