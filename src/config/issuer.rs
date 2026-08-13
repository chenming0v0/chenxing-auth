use std::env;

use super::construction::{parse_root_http_url, validate_cookie_security};
use super::{Config, ConfigError};

impl Config {
    /// 应用数据库里已经持久化的 Issuer，并重新派生 WebAuthn 默认值。
    ///
    /// 显式的 WEBAUTHN_* 环境变量仍然保留覆盖能力；未显式配置时跟随数据库
    /// Issuer，避免首次启动时的 localhost 占位默认值泄漏到完整运行模式。
    pub fn apply_persisted_issuer(&mut self, value: &str) -> Result<(), ConfigError> {
        let issuer_url = normalize_issuer_url(value)?;
        let issuer = parse_root_http_url(&issuer_url, "APP_ISSUER")?;
        validate_cookie_security(&issuer, self.cookie_secure)?;

        let webauthn_rp_id = env::var("WEBAUTHN_RP_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| issuer.host_str().unwrap_or_default().to_owned());
        if webauthn_rp_id.trim().is_empty() {
            return Err(ConfigError::InvalidValue("WEBAUTHN_RP_ID"));
        }
        let webauthn_origin = env::var("WEBAUTHN_ORIGIN")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| issuer_url.clone());
        parse_root_http_url(&webauthn_origin, "WEBAUTHN_ORIGIN")?;

        self.issuer_url = issuer_url;
        self.issuer_configured = true;
        self.webauthn_rp_id = webauthn_rp_id;
        self.webauthn_origin = webauthn_origin;
        Ok(())
    }

    pub fn configured_issuer(&self) -> Option<&str> {
        self.issuer_configured.then_some(self.issuer_url.as_str())
    }

    pub(crate) fn take_legacy_issuer_import(&mut self) -> Option<String> {
        self.legacy_issuer_import.take()
    }
}

/// 规范化并校验可持久化的固定 Issuer。返回值不带尾随斜杠，保证数据库比较稳定。
pub fn normalize_issuer_url(value: &str) -> Result<String, ConfigError> {
    let issuer = parse_root_http_url(value.trim(), "APP_ISSUER")?;
    let mut normalized = issuer.to_string();
    if normalized.ends_with('/') {
        normalized.pop();
    }
    Ok(normalized)
}
