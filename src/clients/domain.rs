use serde::Deserialize;
use thiserror::Error;
use url::{Host, Url};

pub const DEFAULT_MAX_REDIRECT_URIS: usize = 10;
pub const DEFAULT_MAX_REDIRECT_URI_LENGTH: usize = 2_048;
pub const DEFAULT_MAX_SCOPES: usize = 32;
pub const DEFAULT_MAX_SCOPE_LENGTH: usize = 64;
pub const DEFAULT_ALLOWED_SCOPES: &[&str] = &["openid", "profile", "email"];
pub const ABSOLUTE_MAX_REDIRECT_URIS: usize = 100;
pub const ABSOLUTE_MAX_REDIRECT_URI_LENGTH: usize = 8_192;
pub const ABSOLUTE_MAX_SCOPES: usize = 100;
pub const ABSOLUTE_MAX_SCOPE_LENGTH: usize = 256;

fn default_allowed_scopes() -> Vec<String> {
    DEFAULT_ALLOWED_SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ClientAuthMethod {
    #[serde(rename = "client_secret_basic")]
    Basic,
    #[serde(rename = "client_secret_post")]
    Post,
    #[serde(rename = "none")]
    None,
}

impl ClientAuthMethod {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "client_secret_basic" => Some(Self::Basic),
            "client_secret_post" => Some(Self::Post),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "client_secret_basic",
            Self::Post => "client_secret_post",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistrationLimits {
    pub max_redirect_uris: usize,
    pub max_redirect_uri_length: usize,
    pub max_scopes: usize,
    pub max_scope_length: usize,
    pub allowed_scopes: Vec<String>,
}

impl Default for ClientRegistrationLimits {
    fn default() -> Self {
        Self {
            max_redirect_uris: DEFAULT_MAX_REDIRECT_URIS,
            max_redirect_uri_length: DEFAULT_MAX_REDIRECT_URI_LENGTH,
            max_scopes: DEFAULT_MAX_SCOPES,
            max_scope_length: DEFAULT_MAX_SCOPE_LENGTH,
            allowed_scopes: default_allowed_scopes(),
        }
    }
}

impl ClientRegistrationLimits {
    pub fn new(
        max_redirect_uris: usize,
        max_redirect_uri_length: usize,
        max_scopes: usize,
        max_scope_length: usize,
    ) -> Option<Self> {
        if !valid_numeric_limits(
            max_redirect_uris,
            max_redirect_uri_length,
            max_scopes,
            max_scope_length,
        ) {
            return None;
        }
        Some(Self {
            max_redirect_uris,
            max_redirect_uri_length,
            max_scopes,
            max_scope_length,
            allowed_scopes: default_allowed_scopes(),
        })
    }

    pub fn with_allowed_scopes(mut self, allowed_scopes: Vec<String>) -> Option<Self> {
        self.allowed_scopes = normalize_allowed_scopes(allowed_scopes, self.max_scope_length)?;
        Some(self)
    }
}

fn valid_numeric_limits(
    max_redirect_uris: usize,
    max_redirect_uri_length: usize,
    max_scopes: usize,
    max_scope_length: usize,
) -> bool {
    max_redirect_uris > 0
        && max_redirect_uris <= ABSOLUTE_MAX_REDIRECT_URIS
        && max_redirect_uri_length > 0
        && max_redirect_uri_length <= ABSOLUTE_MAX_REDIRECT_URI_LENGTH
        && max_scopes > 0
        && max_scopes <= ABSOLUTE_MAX_SCOPES
        && max_scope_length > 0
        && max_scope_length <= ABSOLUTE_MAX_SCOPE_LENGTH
}

#[derive(Debug, Deserialize)]
pub struct ClientRegistrationInput {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub client_uri: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

pub type ClientUpdateInput = ClientRegistrationInput;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedClientRegistration {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientRegistrationError {
    #[error("client name is invalid")]
    InvalidClientName,
    #[error("at least one redirect URI is required")]
    MissingRedirectUri,
    #[error("too many redirect URIs")]
    TooManyRedirectUris,
    #[error("redirect URI is too long")]
    RedirectUriTooLong,
    #[error("redirect URI must use HTTPS, or HTTP with a loopback IP (127.0.0.1 / [::1])")]
    InsecureRedirectUri,
    #[error("wildcard redirect URI is not allowed")]
    WildcardRedirectUri,
    #[error("redirect URI is invalid")]
    InvalidRedirectUri,
    #[error("at least one scope is required")]
    MissingScope,
    #[error("too many scopes")]
    TooManyScopes,
    #[error("scope is too long")]
    ScopeTooLong,
    #[error("scope is not supported")]
    UnsupportedScope,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("logo URI is invalid")]
    InvalidLogoUri,
    #[error("client URI is invalid")]
    InvalidClientUri,
    #[error("description is invalid")]
    InvalidDescription,
}

pub fn validate_client_registration(
    input: ClientRegistrationInput,
) -> Result<ValidatedClientRegistration, ClientRegistrationError> {
    validate_client_registration_with_limits(input, &ClientRegistrationLimits::default())
}

pub fn validate_client_registration_with_limits(
    input: ClientRegistrationInput,
    limits: &ClientRegistrationLimits,
) -> Result<ValidatedClientRegistration, ClientRegistrationError> {
    let client_name = input.client_name.trim().to_owned();
    if client_name.is_empty() || client_name.chars().count() > 128 {
        return Err(ClientRegistrationError::InvalidClientName);
    }
    if input.redirect_uris.is_empty() {
        return Err(ClientRegistrationError::MissingRedirectUri);
    }
    if input.redirect_uris.len() > limits.max_redirect_uris {
        return Err(ClientRegistrationError::TooManyRedirectUris);
    }

    let redirect_uris = input
        .redirect_uris
        .into_iter()
        .map(|redirect_uri| validate_redirect_uri(redirect_uri, limits))
        .collect::<Result<Vec<_>, _>>()?;

    if input.scopes.is_empty() {
        return Err(ClientRegistrationError::MissingScope);
    }
    if input.scopes.len() > limits.max_scopes {
        return Err(ClientRegistrationError::TooManyScopes);
    }
    let scopes = input
        .scopes
        .into_iter()
        .map(|scope| {
            let scope = scope.trim().to_owned();
            if scope.chars().count() > limits.max_scope_length {
                return Err(ClientRegistrationError::ScopeTooLong);
            }
            if scope.is_empty() || scope.chars().any(char::is_whitespace) {
                Err(ClientRegistrationError::InvalidScope)
            } else {
                Ok(scope)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    if scopes
        .iter()
        .any(|scope| !limits.allowed_scopes.contains(scope))
    {
        return Err(ClientRegistrationError::UnsupportedScope);
    }
    // Duplicate values are accepted and normalized in first-seen order.
    let redirect_uris = deduplicate(redirect_uris);
    let scopes = deduplicate(scopes);
    let logo_uri = crate::clients::presentation::validate_logo_uri(input.logo_uri)?;
    let client_uri = crate::clients::presentation::validate_client_uri(input.client_uri)?;
    let description = crate::clients::presentation::validate_description(input.description)?;

    Ok(ValidatedClientRegistration {
        client_name,
        redirect_uris,
        scopes,
        logo_uri,
        client_uri,
        description,
    })
}

fn normalize_allowed_scopes(scopes: Vec<String>, max_scope_length: usize) -> Option<Vec<String>> {
    if scopes.is_empty() || scopes.len() > ABSOLUTE_MAX_SCOPES {
        return None;
    }
    let scopes = scopes
        .into_iter()
        .map(|scope| {
            let scope = scope.trim().to_owned();
            if scope.is_empty()
                || scope.chars().count() > max_scope_length
                || scope.chars().any(char::is_whitespace)
            {
                None
            } else {
                Some(scope)
            }
        })
        .collect::<Option<Vec<_>>>()?;
    let scopes = deduplicate(scopes);
    (!scopes.is_empty()).then_some(scopes)
}

fn validate_redirect_uri(
    value: String,
    limits: &ClientRegistrationLimits,
) -> Result<String, ClientRegistrationError> {
    let value = value.trim().to_owned();
    if value.chars().count() > limits.max_redirect_uri_length {
        return Err(ClientRegistrationError::RedirectUriTooLong);
    }
    if value.contains('*') {
        return Err(ClientRegistrationError::WildcardRedirectUri);
    }
    let url = Url::parse(&value).map_err(|_| ClientRegistrationError::InvalidRedirectUri)?;

    // Scheme 校验（Issue #69）：
    // - https：允许任意 host，是 Web 机密客户端的标准路径。
    // - http：仅允许字面回环 IP（RFC 8252 §7.3，用于原生/CLI 客户端）：
    //     * IPv4：整个 127.0.0.0/8 段（is_loopback() 语义正确）
    //     * IPv6：::1（唯一回环地址）
    //   明确排除 localhost 域名：localhost 可被 DNS 劫持或解析到非回环地址
    //   （RFC 8252 §8.3 建议使用字面 IP 而非 localhost）。
    // - 其他 scheme（javascript:、data:、自定义 scheme）一律拒绝，防止 XSS/开放重定向。
    match url.scheme() {
        "https" => {}
        "http" => {
            let is_loopback = match url.host() {
                // 整个 127.0.0.0/8 段均为回环，is_loopback() 语义正确
                Some(Host::Ipv4(ip)) => ip.is_loopback(),
                // ::1 是 IPv6 唯一回环地址
                Some(Host::Ipv6(ip)) => ip.is_loopback(),
                // Domain 类型涵盖 localhost 及其他域名，均不视为安全的回环标识
                _ => false,
            };
            if !is_loopback {
                return Err(ClientRegistrationError::InsecureRedirectUri);
            }
        }
        _ => return Err(ClientRegistrationError::InsecureRedirectUri),
    }

    // RFC 6749 §3.1.2：redirect_uri 不得含 fragment。
    // fragment 必须显式拒绝，不能依赖归一化静默丢弃（会掩盖客户端配置错误）。
    if url.fragment().is_some() {
        return Err(ClientRegistrationError::InvalidRedirectUri);
    }
    if url.host_str().is_none() {
        return Err(ClientRegistrationError::InvalidRedirectUri);
    }
    if url.username() != "" || url.password().is_some() {
        return Err(ClientRegistrationError::InvalidRedirectUri);
    }

    // Issue #68: 归一化后落库，防止等价 URI 在授权侧严格 == 比对时失败。
    // url::Url::to_string() 按 WHATWG URL 规范归一化：
    // - 去除默认端口（https:443、http:80）
    // - 补全根路径 trailing slash（https://example.com → https://example.com/）
    //
    // 注意兼容性影响：存量 redirect_uris 可能是非归一化形式（例如带 :443 或缺
    // trailing slash）。升级后这些 client 若按归一化形式发起授权请求，会因授权侧
    // 严格 == 比对失败而返回 RedirectUriNotAllowed，需人工或迁移脚本归一化存量数据。
    canonicalize_redirect_uri(&value).ok_or(ClientRegistrationError::InvalidRedirectUri)
}

/// Return the canonical textual form used for both client registration and
/// authorization-request matching.
///
/// The caller is responsible for applying the registration security policy;
/// this helper only performs URL parsing and serialization so that equivalent
/// representations (for example a bare origin or an explicit default port)
/// have one shared form.
pub fn canonicalize_redirect_uri(value: &str) -> Option<String> {
    Url::parse(value.trim()).ok().map(|url| url.to_string())
}

fn deduplicate(values: Vec<String>) -> Vec<String> {
    values.into_iter().fold(Vec::new(), |mut unique, value| {
        if !unique.contains(&value) {
            unique.push(value);
        }
        unique
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助函数：直接校验单个 redirect URI，返回归一化后的结果
    fn validate_uri(uri: &str) -> Result<String, ClientRegistrationError> {
        validate_redirect_uri(uri.to_owned(), &ClientRegistrationLimits::default())
    }

    // ========== Issue #68: URL 归一化 ==========

    #[test]
    fn redirect_uri_normalizes_bare_origin_adds_trailing_slash() {
        // https://example.com 没有显式路径，归一化补全 trailing slash
        assert_eq!(
            validate_uri("https://example.com").unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn redirect_uri_normalizes_removes_default_https_port() {
        // https:443 是默认端口，归一化时去除
        assert_eq!(
            validate_uri("https://example.com:443/cb").unwrap(),
            "https://example.com/cb"
        );
    }

    #[test]
    fn redirect_uri_with_explicit_path_unchanged() {
        // 显式路径的 URI 归一化后保持不变
        assert_eq!(
            validate_uri("https://example.com/oauth/callback").unwrap(),
            "https://example.com/oauth/callback"
        );
    }

    // ========== Issue #69: RFC 8252 回环地址放开 ==========

    #[test]
    fn redirect_uri_accepts_loopback_ipv4_http() {
        // RFC 8252 §7.3：原生/CLI 客户端可使用回环 HTTP
        assert_eq!(
            validate_uri("http://127.0.0.1:8080/cb").unwrap(),
            "http://127.0.0.1:8080/cb"
        );
    }

    #[test]
    fn redirect_uri_accepts_loopback_ipv6_http() {
        // IPv6 回环地址 ::1
        assert_eq!(
            validate_uri("http://[::1]:8080/cb").unwrap(),
            "http://[::1]:8080/cb"
        );
    }

    #[test]
    fn redirect_uri_accepts_any_loopback_ipv4() {
        // 整个 127.0.0.0/8 段均为回环，is_loopback() 正确处理
        assert_eq!(
            validate_uri("http://127.0.0.2/cb").unwrap(),
            "http://127.0.0.2/cb"
        );
        assert_eq!(
            validate_uri("http://127.255.255.255/cb").unwrap(),
            "http://127.255.255.255/cb"
        );
    }

    #[test]
    fn redirect_uri_rejects_localhost_domain_http() {
        // RFC 8252 §8.3：明确排除 localhost 域名，只接受字面 IP
        // localhost 可能被 DNS 劫持或解析到非回环地址
        assert_eq!(
            validate_uri("http://localhost:8080/cb").unwrap_err(),
            ClientRegistrationError::InsecureRedirectUri,
        );
    }

    #[test]
    fn redirect_uri_rejects_non_loopback_http() {
        // 非回环地址的 HTTP 一律拒绝
        assert_eq!(
            validate_uri("http://example.com/cb").unwrap_err(),
            ClientRegistrationError::InsecureRedirectUri,
        );
    }

    #[test]
    fn redirect_uri_rejects_non_loopback_ipv4_http() {
        // 10.0.0.1 是私有地址但不是回环
        assert_eq!(
            validate_uri("http://10.0.0.1/cb").unwrap_err(),
            ClientRegistrationError::InsecureRedirectUri,
        );
    }

    // ========== 危险 scheme 拒绝 ==========

    #[test]
    fn redirect_uri_rejects_javascript_scheme() {
        // javascript: 会被 url crate 解析成功，但 scheme 非 https/http → InsecureRedirectUri
        assert_eq!(
            validate_uri("javascript:alert(1)").unwrap_err(),
            ClientRegistrationError::InsecureRedirectUri,
        );
    }

    #[test]
    fn redirect_uri_rejects_data_scheme() {
        assert_eq!(
            validate_uri("data:text/html,<script>alert(1)</script>").unwrap_err(),
            ClientRegistrationError::InsecureRedirectUri,
        );
    }

    #[test]
    fn redirect_uri_rejects_custom_scheme() {
        // 自定义 scheme（如移动端 Deep Link）暂不支持
        assert_eq!(
            validate_uri("myapp://callback").unwrap_err(),
            ClientRegistrationError::InsecureRedirectUri,
        );
    }

    // ========== OAuth 2.0 协议约束 ==========

    #[test]
    fn redirect_uri_rejects_fragment() {
        // RFC 6749 §3.1.2：redirect_uri 不得含 fragment
        assert_eq!(
            validate_uri("https://example.com/cb#section").unwrap_err(),
            ClientRegistrationError::InvalidRedirectUri,
        );
    }

    #[test]
    fn redirect_uri_rejects_userinfo() {
        // 已有测试覆盖 (tests/client_domain.rs)，此处确保回归
        assert_eq!(
            validate_uri("https://user:pass@example.com/cb").unwrap_err(),
            ClientRegistrationError::InvalidRedirectUri,
        );
    }
}
