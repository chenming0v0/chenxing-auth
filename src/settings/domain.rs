use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::users::email::EmailAddress;

const MAX_RP_NAME_LENGTH: usize = 128;
const MAX_RP_ID_LENGTH: usize = 253;
const MAX_ORIGINS: usize = 32;
const MAX_DOMAINS: usize = 128;
const MAX_DOMAIN_LENGTH: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyUserVerification {
    #[default]
    Preferred,
    Required,
    Discouraged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyAuthenticatorAttachment {
    #[default]
    Any,
    Platform,
    CrossPlatform,
}

/// 管理 API 与运行时使用的 Passkey 配置。
///
/// 反序列化保持全字段必填：这是 PUT `/admin/settings/passkey` 的请求体。
/// 数据库旧行的缺字段补齐在 `settings::persisted`，不要把 `#[serde(default)]`
/// 加到这个类型上，否则漏字段的 PUT 会按默认值覆盖已保存的限制。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeySetting {
    pub enabled: bool,
    pub rp_name: String,
    pub rp_id: String,
    pub user_verification: PasskeyUserVerification,
    pub authenticator_attachment: PasskeyAuthenticatorAttachment,
    pub allow_insecure_origin: bool,
    pub allowed_origins: Vec<String>,
}

impl Default for PasskeySetting {
    fn default() -> Self {
        Self {
            enabled: true,
            rp_name: "辰星认证中枢".to_owned(),
            rp_id: String::new(),
            user_verification: PasskeyUserVerification::Preferred,
            authenticator_attachment: PasskeyAuthenticatorAttachment::Any,
            allow_insecure_origin: false,
            allowed_origins: Vec::new(),
        }
    }
}

/// 公开注册开关（`POST /api/v1/users` 的准入门）。
///
/// 双布尔默认全关：未配置实例的公开注册保持关闭，管理员必须显式打开。
/// `email_verification_required` 为真时，即使 `enabled` 打开，注册仍在
/// 邮件验证能力缺失处 fail-closed（503），见 `users::service::registration`。
///
/// TODO(Issue #554)：邀请码机制。注册打开后的进一步准入控制（邀请码/审批）
/// 将叠加在本开关之上，本结构届时保持向后兼容。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RegistrationSetting {
    pub enabled: bool,
    pub email_verification_required: bool,
    pub invitation_code_required: bool,
}

impl RegistrationSetting {
    /// 纯布尔结构没有取值校验，保留该入口是为了与其它设置共用同一条
    /// `PersistedDecode::require` / `inspect` 管道。
    pub fn validate(self) -> Result<Self, SettingsValidationError> {
        Ok(self)
    }
}

/// 管理 API 与运行时使用的邮箱域名策略。
///
/// 反序列化保持全字段必填。回读缺字段的兼容转换见 `settings::persisted`：
/// `whitelist_enabled` 缺失必须拒绝，不能按 `false` 补成「放行一切」。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EmailPolicySetting {
    pub whitelist_enabled: bool,
    pub alias_restriction_enabled: bool,
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SettingsValidationError {
    #[error("passkey relying party name is invalid")]
    InvalidPasskeyRpName,
    #[error("passkey relying party id is invalid")]
    InvalidPasskeyRpId,
    #[error("passkey origin is invalid")]
    InvalidPasskeyOrigin,
    #[error("email domain is invalid")]
    InvalidEmailDomain,
    #[error("smtp host is invalid")]
    InvalidSmtpHost,
    #[error("smtp port is invalid")]
    InvalidSmtpPort,
    #[error("smtp username is invalid")]
    InvalidSmtpUsername,
    #[error("smtp sender address is invalid")]
    InvalidSmtpFrom,
    #[error("smtp password is invalid")]
    InvalidSmtpPassword,
    #[error("smtp password action conflicts with password field")]
    SmtpPasswordConflict,
    #[error("smtp password is required when password_action is set")]
    SmtpPasswordRequired,
    #[error("security limit field is invalid: {0}")]
    InvalidSecurityLimit(&'static str),
    #[error("browser session lifetime is invalid")]
    InvalidSessionLifetime,
}

impl PasskeySetting {
    pub fn with_runtime_defaults(mut self, rp_id: &str, origin: &str) -> Self {
        if self.rp_id.trim().is_empty() {
            self.rp_id = rp_id.trim().to_owned();
        }
        if self.allowed_origins.is_empty() {
            let origin = origin.trim();
            if !origin.is_empty() {
                self.allowed_origins.push(origin.to_owned());
            }
        }
        if self.rp_name.trim().is_empty() {
            self.rp_name = "辰星认证中枢".to_owned();
        }
        self
    }

    pub fn validate(self) -> Result<Self, SettingsValidationError> {
        let rp_name = self.rp_name.trim().to_owned();
        if rp_name.is_empty() || rp_name.chars().count() > MAX_RP_NAME_LENGTH {
            return Err(SettingsValidationError::InvalidPasskeyRpName);
        }
        let rp_id = self.rp_id.trim().to_ascii_lowercase();
        if !is_registrable_rp_id(&rp_id) {
            return Err(SettingsValidationError::InvalidPasskeyRpId);
        }
        let allowed_origins = normalize_origins(self.allowed_origins, self.allow_insecure_origin)?;
        if allowed_origins.is_empty() {
            return Err(SettingsValidationError::InvalidPasskeyOrigin);
        }
        // origin 白名单按「host 等于 rp_id 或是它的子域」判定。这条后缀规则只有在
        // rp_id 是可注册域时才构成信任边界，因此 rp_id 的点号要求（见
        // `is_registrable_rp_id`）是这里的前置条件，不能单独放宽。
        for origin in &allowed_origins {
            let url =
                Url::parse(origin).map_err(|_| SettingsValidationError::InvalidPasskeyOrigin)?;
            let host = url
                .host_str()
                .ok_or(SettingsValidationError::InvalidPasskeyOrigin)?
                .to_ascii_lowercase();
            if !(host == rp_id || host.ends_with(&format!(".{rp_id}"))) {
                return Err(SettingsValidationError::InvalidPasskeyOrigin);
            }
        }
        Ok(Self {
            enabled: self.enabled,
            rp_name,
            rp_id,
            user_verification: self.user_verification,
            authenticator_attachment: self.authenticator_attachment,
            allow_insecure_origin: self.allow_insecure_origin,
            allowed_origins,
        })
    }
}

impl EmailPolicySetting {
    pub fn validate(self) -> Result<Self, SettingsValidationError> {
        let mut allowed_domains = Vec::new();
        for domain in self.allowed_domains {
            let domain = domain.trim();
            if domain.is_empty() {
                continue;
            }
            if domain.chars().count() > MAX_DOMAIN_LENGTH || domain.contains('@') {
                return Err(SettingsValidationError::InvalidEmailDomain);
            }
            // 白名单存 IDNA 匹配形态：管理员填 `éxample.com` 与填
            // `xn--xample-9ua.com` 必须落到同一个键，否则同一个域名的两种写法里
            // 只有一种能命中（Issue #302）。空标签、根点、超长标签和非法
            // Punycode 都由 `canonical_domain` 一并拒绝，不再手写字符白名单。
            let domain = crate::users::email::canonical_domain(domain)
                .map_err(|_| SettingsValidationError::InvalidEmailDomain)?;
            if !allowed_domains.contains(&domain) {
                allowed_domains.push(domain);
            }
            if allowed_domains.len() > MAX_DOMAINS {
                return Err(SettingsValidationError::InvalidEmailDomain);
            }
        }
        if self.whitelist_enabled && allowed_domains.is_empty() {
            return Err(SettingsValidationError::InvalidEmailDomain);
        }
        Ok(Self {
            whitelist_enabled: self.whitelist_enabled,
            alias_restriction_enabled: self.alias_restriction_enabled,
            allowed_domains,
        })
    }

    /// 判定一个已规范化的邮箱是否被策略放行。
    ///
    /// 入参是 [`EmailAddress`] 而不是 `&str`：白名单比较的是 IDNA 匹配域名，
    /// 自己再 `to_ascii_lowercase` 一遍会在 Unicode 域名上算出与 `canonical_email`
    /// 不同的键，白名单就永远不命中（Issue #302）。域名的规范化规则只有一处，
    /// 就是 `EmailAddress`。
    pub fn allows_email(&self, email: &EmailAddress) -> bool {
        // 别名限制看匹配值的本地部分：匹配值不剥离 `+`，因此这里能看到真实别名。
        if self.alias_restriction_enabled && email.canonical_local_part().contains('+') {
            return false;
        }
        if !self.whitelist_enabled {
            return true;
        }
        let domain = email.canonical_domain();
        self.allowed_domains.iter().any(|allowed| domain == allowed)
    }
}

/// WebAuthn rp_id 必须是可注册域（Issue #287，#452）。
///
/// origin 校验用 `host == rp_id || host.ends_with(".{rp_id}")`。单标签 rp_id 会让
/// 这条后缀规则退化成通配：`rp_id = "com"` 时 `https://evil.com` 也能进白名单。
/// 因此要求至少含一个点号，并进一步用 Public Suffix List 拒绝本身就是公共后缀的
/// 值（`co.uk`、`com.cn`、`github.io` 等）：把后缀当 rp_id 会让所有子域共享同一条
/// 信任边界，浏览器端 WebAuthn 也拒绝这类 rp_id。
///
/// 例外只保留两类：
/// - `localhost`：RFC 6761 保证它（以及 `*.localhost`）指向回环，不存在被他人注册
///   的可能，而本地开发依赖它——`Config` 在缺少 `WEBAUTHN_RP_ID` 时就会从 issuer
///   host 填出这个值。
/// - IPv4：WebAuthn 规范允许 IP 地址作为 rp_id，PSL 不覆盖 IP，按规范放行
///   （`127.0.0.1` 之类内网地址）。IPv6 无法通过下方字符白名单，天然被拒。
fn is_registrable_rp_id(rp_id: &str) -> bool {
    if rp_id.is_empty()
        || rp_id.chars().count() > MAX_RP_ID_LENGTH
        || rp_id.starts_with('.')
        || rp_id.ends_with('.')
        || rp_id.contains("..")
        || !rp_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '.'
        })
    {
        return false;
    }
    if rp_id == "localhost" {
        return true;
    }
    // 严格四段十进制 IPv4，避免 url 规范里 `123` 这类宽松解析被当作地址放行。
    if rp_id.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    // `psl::domain_str` 返回 eTLD+1；公共后缀本身返回 None。rp_id 已在上层
    // `validate` 转成 ASCII 小写，Punycode 形式（`xn--…`）直接命中 PSL 数据。
    psl::domain_str(rp_id).is_some()
}

fn normalize_origins(
    origins: Vec<String>,
    allow_insecure_origin: bool,
) -> Result<Vec<String>, SettingsValidationError> {
    let mut normalized = Vec::new();
    for origin in origins {
        for part in origin.split([',', ' ', '\n', '\r', '\t']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let url =
                Url::parse(part).map_err(|_| SettingsValidationError::InvalidPasskeyOrigin)?;
            if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
                return Err(SettingsValidationError::InvalidPasskeyOrigin);
            }
            if !url.username().is_empty() || url.password().is_some() {
                return Err(SettingsValidationError::InvalidPasskeyOrigin);
            }
            let scheme_ok = match url.scheme() {
                "https" => true,
                "http" => allow_insecure_origin || is_loopback_host(&url),
                _ => false,
            };
            if !scheme_ok || url.host_str().is_none() {
                return Err(SettingsValidationError::InvalidPasskeyOrigin);
            }
            let value = origin_key(&url)?;
            if !normalized.contains(&value) {
                normalized.push(value);
            }
            if normalized.len() > MAX_ORIGINS {
                return Err(SettingsValidationError::InvalidPasskeyOrigin);
            }
        }
    }
    Ok(normalized)
}

fn origin_key(url: &Url) -> Result<String, SettingsValidationError> {
    let host = url
        .host_str()
        .ok_or(SettingsValidationError::InvalidPasskeyOrigin)?
        .to_ascii_lowercase();
    Ok(match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    })
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
#[path = "domain_tests.rs"]
mod tests;
