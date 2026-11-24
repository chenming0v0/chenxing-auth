use crate::users::domain::UserId;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// OAuth `state` 最多允许的 Unicode 字符数量。
pub const MAX_STATE_LENGTH: usize = 512;
/// OIDC `nonce` 最多允许的 Unicode 字符数量。
pub const MAX_NONCE_LENGTH: usize = 512;
/// `max_age` 与 Unix 秒数比较，必须能由共享时钟的有符号时间戳表示。
pub const MAX_MAX_AGE: u64 = i64::MAX as u64;

#[derive(Clone, Deserialize, Serialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    /// 当前仅支持 `query`；未提供时使用授权码流程的默认响应模式。
    pub response_mode: Option<String>,
    /// OIDC Request Object；不支持时必须显式拒绝，不能静默丢弃。
    pub request: Option<String>,
    /// OIDC Request Object 地址；当前不支持，也不会拉取远端内容。
    pub request_uri: Option<String>,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// OIDC `prompt` 值，以空格分隔。
    pub prompt: Option<String>,
    /// 允许的认证事件最大年龄，单位为秒。
    pub max_age: Option<u64>,
}

impl fmt::Debug for AuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationRequest")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("response_type", &self.response_type)
            .field("response_mode", &self.response_mode)
            .field("request", &self.request.as_ref().map(|_| "<redacted>"))
            .field(
                "request_uri",
                &self.request_uri.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .field("state", &self.state.as_ref().map(|_| "<redacted>"))
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field(
                "code_challenge",
                &self.code_challenge.as_ref().map(|_| "<redacted>"),
            )
            .field("code_challenge_method", &self.code_challenge_method)
            .field("prompt", &self.prompt)
            .field("max_age", &self.max_age)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub owner_user_id: Option<UserId>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub description: Option<String>,
    pub numeric_app_id: i64,
    pub android_package: Option<String>,
    pub quota_exempt: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedAuthorizationRequest {
    pub client_id: String,
    /// 授权请求提交的原始 `redirect_uri` 文本。
    ///
    /// 注册匹配使用 canonical 形式，但授权码必须绑定这份原始文本；Token
    /// 端点只接受同一原始值，不能把 `:443`、根斜杠等文本差异再规范化掉。
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    /// 规范化后的 OIDC `prompt`；`None` 使用默认交互策略。
    pub prompt: Option<String>,
    pub max_age: Option<u64>,
    /// 请求需要重新认证时由处理器设置，并记录原会话摘要作为重认证围栏。
    pub reauth_required: bool,
    pub reauth_session_token_hash: Option<String>,
    pub owner_user_id: Option<UserId>,
    /// 发起该授权请求的浏览器会话令牌 SHA-256 摘要，用于把签发出的授权码绑定到会话。
    ///
    /// 协议校验阶段拿不到会话（`/oauth/authorize` 的查询参数里不该、也不能带
    /// 会话凭据，否则会话令牌会进 Referer 和访问日志），因此
    /// `validate_authorization_request` 一律填 `None`，由持有会话的调用方
    /// （`handlers::authorize_request` / 授权确认页）在校验之后回填。
    pub session_token_hash: Option<String>,
}

impl fmt::Debug for ValidatedAuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedAuthorizationRequest")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("state", &"<redacted>")
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field("code_challenge", &"<redacted>")
            .field("prompt", &self.prompt)
            .field("max_age", &self.max_age)
            .field("reauth_required", &self.reauth_required)
            .field(
                "reauth_session_token_hash",
                &self
                    .reauth_session_token_hash
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("owner_user_id", &self.owner_user_id)
            .field(
                "session_token_hash",
                &self.session_token_hash.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationRequestError {
    #[error("client id is invalid")]
    InvalidClient,
    #[error("redirect URI is not registered")]
    RedirectUriNotAllowed,
    #[error("response type must be code")]
    UnsupportedResponseType,
    #[error("response mode must be query")]
    UnsupportedResponseMode,
    #[error("request parameter is not supported")]
    RequestNotSupported,
    #[error("request_uri parameter is not supported")]
    RequestUriNotSupported,
    #[error("requested scope is not allowed")]
    ScopeNotAllowed,
    #[error("state is required")]
    MissingState,
    #[error("state is too long")]
    StateTooLong,
    #[error("nonce is too long")]
    NonceTooLong,
    #[error("prompt is invalid")]
    InvalidPrompt,
    #[error("prompt=none cannot be combined with another prompt value")]
    PromptNoneCombined,
    #[error("max_age is too large")]
    MaxAgeTooLarge,
    #[error("PKCE S256 is required")]
    PkceRequired,
    #[error("PKCE S256 challenge is invalid")]
    InvalidCodeChallenge,
}
