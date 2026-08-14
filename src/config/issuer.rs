use std::fmt;

use super::construction::{parse_root_http_url, validate_cookie_security};
use super::{Config, ConfigError};

/// 已规范化、不可为空的 OIDC Issuer。
///
/// 构造函数只接受无 userinfo、path、query、fragment 的 http(s) 根 URL，内部字符串
/// 永远不带尾随斜杠。协议签发与验证函数接收这个类型，而不是裸 `&str`，从类型层
/// 消除 `iss: ""` 和相对 Discovery 端点。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct IssuerUrl {
    normalized: String,
    parsed: url::Url,
}

impl IssuerUrl {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let parsed = parse_root_http_url(value.trim(), "APP_ISSUER")?;
        let mut normalized = parsed.to_string();
        if normalized.ends_with('/') {
            normalized.pop();
        }
        Ok(Self { normalized, parsed })
    }

    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    pub fn host_str(&self) -> &str {
        // `parse_root_http_url` 已保证 host 存在。
        self.parsed.host_str().unwrap_or_default()
    }

    pub fn is_https(&self) -> bool {
        self.parsed.scheme() == "https"
    }

    pub(crate) fn parsed(&self) -> &url::Url {
        &self.parsed
    }

    pub fn join_path(&self, path: &str) -> String {
        debug_assert!(path.starts_with('/'));
        format!("{}{path}", self.normalized)
    }
}

impl AsRef<str> for IssuerUrl {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for IssuerUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for IssuerUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("IssuerUrl")
            .field(&self.as_str())
            .finish()
    }
}

impl Config {
    /// 应用数据库里已经持久化的 Issuer，并重新派生 WebAuthn 默认值。
    ///
    /// 显式的 WEBAUTHN_* 环境变量仍然保留覆盖能力；未显式配置时跟随数据库
    /// Issuer，避免首次启动时的 localhost 占位默认值泄漏到完整运行模式。
    pub fn apply_persisted_issuer(&mut self, value: &str) -> Result<(), ConfigError> {
        let issuer = IssuerUrl::parse(value)?;
        validate_cookie_security(&issuer.parsed, self.cookie_secure)?;

        let webauthn_rp_id = if self.webauthn_rp_id_explicit {
            self.webauthn_rp_id.clone()
        } else {
            issuer.host_str().to_owned()
        };
        if webauthn_rp_id.trim().is_empty() {
            return Err(ConfigError::InvalidValue("WEBAUTHN_RP_ID"));
        }
        let webauthn_origin = if self.webauthn_origin_explicit {
            self.webauthn_origin.clone()
        } else {
            issuer.as_str().to_owned()
        };
        parse_root_http_url(&webauthn_origin, "WEBAUTHN_ORIGIN")?;

        self.issuer = Some(issuer);
        self.webauthn_rp_id = webauthn_rp_id;
        self.webauthn_origin = webauthn_origin;
        Ok(())
    }

    pub fn configured_issuer(&self) -> Option<&IssuerUrl> {
        self.issuer.as_ref()
    }

    pub(crate) fn take_legacy_issuer_import(&mut self) -> Option<String> {
        self.legacy_issuer_import.take()
    }
}

/// 规范化并校验可持久化的固定 Issuer。返回值不带尾随斜杠，保证数据库比较稳定。
pub fn normalize_issuer_url(value: &str) -> Result<String, ConfigError> {
    IssuerUrl::parse(value).map(|issuer| issuer.normalized)
}
