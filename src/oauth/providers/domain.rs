use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use url::Url;

use super::{
    claims::ClaimMapping,
    endpoint_policy::{EndpointPolicy, validate_endpoint_url},
};

const MAX_NAME_LENGTH: usize = 128;
const MAX_SLUG_LENGTH: usize = 64;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    #[default]
    Basic,
    RequestBody,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ProviderInput {
    pub name: String,
    pub slug: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    #[serde(default = "default_email_claim")]
    pub email_claim: String,
    pub name_claim: Option<String>,
    /// 指向布尔型邮箱验证状态的 claim 路径，必填。
    ///
    /// 线上契约上它仍是可省略字段（旧客户端不会收到 422），但省略会在
    /// `validate()` 里被拒成 400 `invalid_oauth_provider`。缺少它的 provider
    /// 无法判断外部邮箱是否已验证，只能拒绝配置（Issue #261）。
    pub email_verified_claim: Option<String>,
    #[serde(default)]
    pub client_auth_method: ClientAuthMethod,
    /// 是否对该外部 IdP 使用 PKCE（RFC 9700 §2.1.1 要求所有授权码流程都用 PKCE）。
    /// 默认开启；只有确认外部 IdP 不支持 PKCE 时才显式关闭，不做全局禁用。
    #[serde(default = "default_pkce_enabled")]
    pub pkce_enabled: bool,
}

impl fmt::Debug for ProviderInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderInput")
            .field("name", &self.name)
            .field("slug", &self.slug)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("scopes", &self.scopes)
            .field("subject_claim", &self.subject_claim)
            .field("email_claim", &self.email_claim)
            .field("name_claim", &self.name_claim)
            .field("email_verified_claim", &self.email_verified_claim)
            .field("client_auth_method", &self.client_auth_method)
            .field("pkce_enabled", &self.pkce_enabled)
            .finish()
    }
}

/// 自定义 provider 的身份信任模型标识（Issue #296）。
///
/// 语义是明确且收敛的：**OAuth 2.0 授权码流程 + UserInfo 端点**。身份事实
/// （`sub`、`email`、`email_verified`）全部来自用 access token 经 TLS 取回的
/// UserInfo 响应；令牌响应里的 `id_token` 不被解析，也不参与身份判定。
///
/// 之所以把它作为响应字段而不是只写在文档里：这是 API 消费方唯一能据此判断
/// 「本平台对这个 provider 做了什么校验」的信号。文档会过期，字段不会。
///
/// 本平台自身作为 OP 对下游 Client 仍然签发并支持 OIDC ID Token；这个常量只描述
/// 上游自定义 provider 这一侧。要新增 OIDC 依赖方模式（固定 issuer/JWKS/算法策略、
/// 验证签名与 `iss`/`aud`/`exp`/`iat`/`nonce`/`kid`），应当新增一个取值，而不是
/// 放宽这个取值的含义。
pub const PROVIDER_TRUST_MODEL: &str = "oauth2_userinfo";

#[derive(Debug, Clone, Serialize)]
pub struct ProviderSummary {
    pub id: i64,
    pub name: String,
    pub slug: String,
    /// 恒为 [`PROVIDER_TRUST_MODEL`]。见该常量的说明：这里不存在 OIDC 模式。
    pub trust_model: &'static str,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub subject_claim: String,
    pub email_claim: String,
    pub name_claim: Option<String>,
    pub email_verified_claim: Option<String>,
    pub client_auth_method: ClientAuthMethod,
    pub pkce_enabled: bool,
    pub status: String,
    pub client_secret_configured: bool,
}

impl ProviderSummary {
    /// Same claim-path gate as [`ProviderRecord::claim_mapping`].
    ///
    /// Public listing returns summaries, not records. Login must still hide
    /// providers whose `email_verified_claim` is missing or whose paths cannot
    /// form a mapping.
    pub fn claim_mapping(&self) -> Result<ClaimMapping, ProviderValidationError> {
        ClaimMapping::new(
            self.subject_claim.clone(),
            self.email_claim.clone(),
            self.name_claim.clone(),
            self.email_verified_claim.clone(),
        )
    }
}

#[derive(Clone)]
pub struct ValidatedProviderInput {
    pub name: String,
    pub slug: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub userinfo_endpoint: Url,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    /// 已校验的 claim 路径集合，必然包含 `email_verified`。
    pub claims: ClaimMapping,
    pub client_auth_method: ClientAuthMethod,
    pub pkce_enabled: bool,
}

impl fmt::Debug for ValidatedProviderInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedProviderInput")
            .field("name", &self.name)
            .field("slug", &self.slug)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("scopes", &self.scopes)
            .field("claims", &self.claims)
            .field("client_auth_method", &self.client_auth_method)
            .field("pkce_enabled", &self.pkce_enabled)
            .finish()
    }
}

#[derive(Clone)]
pub struct ProviderRecord {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub userinfo_endpoint: Url,
    pub client_id: String,
    pub client_secret_ciphertext: Vec<u8>,
    pub scopes: Vec<String>,
    pub subject_claim: String,
    pub email_claim: String,
    pub name_claim: Option<String>,
    /// 保持 `Option`：数据库列可空，存量行可能是 NULL。
    /// 读取时不报错（管理员需要看到这些行才能修复），使用时由
    /// [`ProviderRecord::claim_mapping`] 拒绝。
    pub email_verified_claim: Option<String>,
    pub client_auth_method: ClientAuthMethod,
    pub pkce_enabled: bool,
    pub status: String,
}

impl fmt::Debug for ProviderRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("slug", &self.slug)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret_ciphertext", &"<redacted>")
            .field("scopes", &self.scopes)
            .field("subject_claim", &self.subject_claim)
            .field("email_claim", &self.email_claim)
            .field("name_claim", &self.name_claim)
            .field("email_verified_claim", &self.email_verified_claim)
            .field("client_auth_method", &self.client_auth_method)
            .field("pkce_enabled", &self.pkce_enabled)
            .field("status", &self.status)
            .finish()
    }
}

/// 判定字符串能否作为外部 OAuth provider 的 slug。
///
/// slug 会拼进回调 URL 和 Set-Cookie 的 Path 属性，因此只放行安全字符集
/// （ASCII 小写字母、数字、`-`、`_`）并限制长度。管理员创建 provider 与
/// `/auth/external/{slug}` 系列路由共用这一条规则；路由侧必须在把路径参数
/// 用于任何 Cookie、日志或审计之前先拒绝非法 slug（Issue #344）。
pub fn is_valid_provider_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.chars().count() <= MAX_SLUG_LENGTH
        && slug.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || character == '_'
        })
}

impl ProviderInput {
    /// 校验并收敛输入。`policy` 是出网边界策略（Issue #343）：生产策略拒绝回环
    /// 端点，开发策略放行回环与明文 `http`。校验端点之外的规则与策略无关。
    pub fn validate(
        self,
        policy: EndpointPolicy,
    ) -> Result<ValidatedProviderInput, ProviderValidationError> {
        let name = self.name.trim().to_owned();
        if name.is_empty() || name.chars().count() > MAX_NAME_LENGTH {
            return Err(ProviderValidationError::InvalidName);
        }
        let slug = self.slug.trim().to_owned();
        if !is_valid_provider_slug(&slug) {
            return Err(ProviderValidationError::InvalidSlug);
        }
        let authorization_endpoint = validate_endpoint(&self.authorization_endpoint, policy)?;
        let token_endpoint = validate_endpoint(&self.token_endpoint, policy)?;
        let userinfo_endpoint = validate_endpoint(&self.userinfo_endpoint, policy)?;
        let client_id = self.client_id.trim().to_owned();
        if client_id.is_empty() || client_id.chars().count() > 512 {
            return Err(ProviderValidationError::InvalidClientId);
        }
        if self.client_secret.as_ref().is_some_and(String::is_empty) {
            return Err(ProviderValidationError::InvalidClientSecret);
        }
        let scopes = normalize_scopes(self.scopes)?;
        let claims = ClaimMapping::new(
            self.subject_claim,
            self.email_claim,
            self.name_claim,
            self.email_verified_claim,
        )?;

        Ok(ValidatedProviderInput {
            name,
            slug,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            client_id,
            client_secret: self.client_secret,
            scopes,
            claims,
            client_auth_method: self.client_auth_method,
            pkce_enabled: self.pkce_enabled,
        })
    }
}

impl ProviderRecord {
    /// 把存储行里的 claim 路径收敛成一个可用的映射。
    ///
    /// 存量行的 `email_verified_claim` 可能是 NULL（该列在 provider 功能上线时
    /// 就是可空的）。这类 provider 无法判断外部邮箱是否已验证，所有使用它的路径
    /// 都必须在这里失败，而不是退化成「当作已验证」。
    pub fn claim_mapping(&self) -> Result<ClaimMapping, ProviderValidationError> {
        ClaimMapping::new(
            self.subject_claim.clone(),
            self.email_claim.clone(),
            self.name_claim.clone(),
            self.email_verified_claim.clone(),
        )
    }

    pub fn summary(&self) -> ProviderSummary {
        ProviderSummary {
            id: self.id,
            name: self.name.clone(),
            slug: self.slug.clone(),
            trust_model: PROVIDER_TRUST_MODEL,
            authorization_endpoint: self.authorization_endpoint.to_string(),
            token_endpoint: self.token_endpoint.to_string(),
            userinfo_endpoint: self.userinfo_endpoint.to_string(),
            client_id: self.client_id.clone(),
            scopes: self.scopes.clone(),
            subject_claim: self.subject_claim.clone(),
            email_claim: self.email_claim.clone(),
            name_claim: self.name_claim.clone(),
            email_verified_claim: self.email_verified_claim.clone(),
            client_auth_method: self.client_auth_method,
            pkce_enabled: self.pkce_enabled,
            status: self.status.clone(),
            client_secret_configured: !self.client_secret_ciphertext.is_empty(),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderValidationError {
    #[error("provider name is invalid")]
    InvalidName,
    #[error("provider slug is invalid")]
    InvalidSlug,
    #[error("provider endpoint is invalid")]
    InvalidEndpoint,
    /// 端点指向私网/链路本地/CGNAT/ULA 等非公网地址（Issue #291）。
    ///
    /// 与 `InvalidEndpoint` 分开是为了让管理员知道该改什么：形态没问题，是目标
    /// 地址空间不允许。消息只描述规则，不回显解析到的地址或内部网络拓扑。
    #[error("provider endpoint must not target a non-public network address")]
    PrivateEndpoint,
    #[error("provider client id is invalid")]
    InvalidClientId,
    #[error("provider client secret is invalid")]
    InvalidClientSecret,
    #[error("provider scope is invalid")]
    InvalidScope,
    #[error("provider claim path is invalid")]
    InvalidClaimPath,
    #[error("email_verified_claim is required")]
    MissingEmailVerifiedClaim,
    #[error("external subject is missing")]
    MissingSubject,
    #[error("external email is invalid")]
    InvalidEmail,
    #[error("external email is not verified")]
    EmailNotVerified,
}

fn validate_endpoint(value: &str, policy: EndpointPolicy) -> Result<Url, ProviderValidationError> {
    let url = Url::parse(value.trim()).map_err(|_| ProviderValidationError::InvalidEndpoint)?;
    validate_endpoint_url(&url, policy)?;
    Ok(url)
}

fn normalize_scopes(scopes: Vec<String>) -> Result<Vec<String>, ProviderValidationError> {
    let mut normalized = Vec::new();
    for scope in scopes {
        let scope = scope.trim().to_owned();
        if scope.is_empty()
            || scope.chars().count() > 128
            || scope.chars().any(char::is_whitespace)
            || normalized.contains(&scope)
        {
            return Err(ProviderValidationError::InvalidScope);
        }
        normalized.push(scope);
    }
    if normalized.is_empty() {
        return Err(ProviderValidationError::InvalidScope);
    }
    Ok(normalized)
}

fn default_subject_claim() -> String {
    "sub".to_owned()
}
fn default_email_claim() -> String {
    "email".to_owned()
}

/// PKCE 默认开启：RFC 9700 §2.1.1 要求所有授权码流程都使用 PKCE。
/// 未显式提供该字段的旧请求体自动获得安全默认值。
fn default_pkce_enabled() -> bool {
    true
}
