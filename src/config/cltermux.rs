use std::env;

use sha2::{Digest, Sha256};

use super::ConfigError;
use super::construction::parse_root_http_url;

const CLTERMUX_TOKEN_MIN_BYTES: usize = 32;

const CLTERMUX_BASE_URL_ENV: &str = "CLTERMUX_PROVIDER_BASE_URL";
const CLTERMUX_OUTBOUND_TOKEN_ENV: &str = "CLTERMUX_INTEROP_OUTBOUND_TOKEN";
const CLTERMUX_INBOUND_TOKEN_ENV: &str = "CLTERMUX_INTEROP_INBOUND_TOKEN";
const CLTERMUX_ALLOWED_CLIENTS_ENV: &str = "CLTERMUX_ALLOWED_CLIENT_IDS";

const COMMON_WEAK_VALUES: &[&str] = &[
    "change-me",
    "changeme",
    "cltermux",
    "cltermux-token",
    "default",
    "default-token",
    "dev",
    "dev-token",
    "example",
    "example-token",
    "interop",
    "interop-token",
    "password",
    "password123",
    "secret",
    "secret-token",
    "test",
    "test-token",
];

const PUBLIC_PLACEHOLDER_MARKERS: &[&str] = &[
    "change-this-token",
    "example-token",
    "insert-token-here",
    "put-your-token-here",
    "replace-me",
    "replace-this-token",
    "your-token",
];

/// CLtermux 服务端到服务端集成配置（Issue #706）。
///
/// 安全边界：
/// - `outbound_token` 是辰星→CLtermux 的 Bearer 原值，只保存在内存里用于发请求，
///   Debug 输出必须脱敏，绝不落库/日志。
/// - `inbound_token_digest` 是 CLtermux→辰星 入站 Bearer 的 SHA-256 摘要。原值在
///   读取后立即丢弃，Config 只持有摘要，验证时对呈现值重新计算摘要做常量时间
///   比较（见 `crate::integrations::cltermux::validation`）。
/// - 任一 token 为空即整个集成禁用（`None`），不存在"半启用"状态：出站无凭据
///   或入站无校验基准都是不可接受的安全姿态。
#[derive(Clone, PartialEq, Eq)]
pub struct CltermuxConfig {
    pub base_url: url::Url,
    pub outbound_token: String,
    pub inbound_token_digest: Vec<u8>,
    /// OAuth Client IDs allowed to use the CLtermux business scope.
    pub allowed_client_ids: Vec<String>,
}

impl std::fmt::Debug for CltermuxConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CltermuxConfig")
            .field("base_url", &self.base_url.as_str())
            .field("outbound_token", &"REDACTED")
            .field("inbound_token_digest", &"REDACTED")
            .finish()
    }
}

pub fn cltermux_config_from_env() -> Result<Option<CltermuxConfig>, ConfigError> {
    let base_url_raw = env::var(CLTERMUX_BASE_URL_ENV).unwrap_or_default();
    let outbound_token = env::var(CLTERMUX_OUTBOUND_TOKEN_ENV).unwrap_or_default();
    let inbound_token = env::var(CLTERMUX_INBOUND_TOKEN_ENV).unwrap_or_default();
    let allowed_clients_raw = env::var(CLTERMUX_ALLOWED_CLIENTS_ENV).unwrap_or_default();

    // 空值 = 集成禁用。三个变量必须同时配置或同时缺席，避免出现
    // "能出站但入站无校验"或"入站有基准但出站无凭据"的半启用姿态。
    if base_url_raw.trim().is_empty()
        && outbound_token.is_empty()
        && inbound_token.is_empty()
        && allowed_clients_raw.trim().is_empty()
    {
        return Ok(None);
    }
    if base_url_raw.trim().is_empty() {
        return Err(ConfigError::MissingValue(CLTERMUX_BASE_URL_ENV));
    }
    if outbound_token.is_empty() {
        return Err(ConfigError::MissingValue(CLTERMUX_OUTBOUND_TOKEN_ENV));
    }
    if inbound_token.is_empty() {
        return Err(ConfigError::MissingValue(CLTERMUX_INBOUND_TOKEN_ENV));
    }
    let allowed_client_ids = parse_allowed_client_ids(&allowed_clients_raw)?;

    validate_interop_token(&outbound_token, CLTERMUX_OUTBOUND_TOKEN_ENV)?;
    validate_interop_token(&inbound_token, CLTERMUX_INBOUND_TOKEN_ENV)?;

    // 出站目标必须 https：该 URL 会承载出站 Bearer 与用户业务凭据，明文 http
    // 会让凭据暴露在链路上。回环 http 开发例外不适用于服务端集成——本机联调
    // 应使用本地 https 或隧道，而不是放宽这条边界。
    let parsed = parse_root_http_url(&base_url_raw, CLTERMUX_BASE_URL_ENV)?;
    if parsed.scheme() != "https" {
        return Err(ConfigError::InvalidValue(CLTERMUX_BASE_URL_ENV));
    }

    // 入站 token 读入后立即归约为摘要，原值在此处结束生命周期。
    let inbound_token_digest = Sha256::digest(inbound_token.as_bytes()).to_vec();

    Ok(Some(CltermuxConfig {
        base_url: parsed,
        outbound_token,
        inbound_token_digest,
        allowed_client_ids,
    }))
}

fn parse_allowed_client_ids(raw: &str) -> Result<Vec<String>, ConfigError> {
    let mut ids = Vec::new();
    for value in raw.split(',') {
        let value = value.trim();
        if value.is_empty()
            || value.len() > 128
            || value.chars().any(char::is_whitespace)
            || ids.iter().any(|existing| existing == value)
        {
            return Err(ConfigError::InvalidValue(CLTERMUX_ALLOWED_CLIENTS_ENV));
        }
        ids.push(value.to_owned());
    }
    if ids.is_empty() {
        return Err(ConfigError::MissingValue(CLTERMUX_ALLOWED_CLIENTS_ENV));
    }
    Ok(ids)
}

pub(crate) fn validate_interop_token(token: &str, name: &'static str) -> Result<(), ConfigError> {
    let normalized = token.to_ascii_lowercase();
    let is_common_weak_value = COMMON_WEAK_VALUES.contains(&normalized.as_str());
    let is_public_placeholder = PUBLIC_PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker));

    if token.len() < CLTERMUX_TOKEN_MIN_BYTES
        || token.chars().any(char::is_whitespace)
        || is_common_weak_value
        || is_public_placeholder
    {
        return Err(ConfigError::InvalidValue(name));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TOKEN: &str = "cltermux-interop-token-0123456789abcdef";

    fn https_base_url() -> String {
        "https://cltermux.example.com/".to_owned()
    }

    #[test]
    fn all_empty_disables_integration() {
        assert_eq!(cltermux_config_from_env(), Ok(None));
    }

    #[test]
    fn partial_configuration_is_rejected() {
        // 只配 base_url 而缺 token：半启用姿态必须 fail-closed。
        let result = with_env(https_base_url(), "", "");
        assert_eq!(
            result,
            Err(ConfigError::MissingValue(CLTERMUX_OUTBOUND_TOKEN_ENV))
        );
    }

    #[test]
    fn http_base_url_is_rejected() {
        let result = with_env(
            "http://cltermux.example.com/".to_owned(),
            VALID_TOKEN,
            VALID_TOKEN,
        );
        assert_eq!(
            result,
            Err(ConfigError::InvalidValue(CLTERMUX_BASE_URL_ENV))
        );
    }

    #[test]
    fn short_tokens_are_rejected() {
        let result = with_env(https_base_url(), "short-token", VALID_TOKEN);
        assert_eq!(
            result,
            Err(ConfigError::InvalidValue(CLTERMUX_OUTBOUND_TOKEN_ENV))
        );
    }

    #[test]
    fn placeholder_tokens_are_rejected() {
        let result = with_env(
            https_base_url(),
            VALID_TOKEN,
            "replace-this-token-with-a-long-value",
        );
        assert_eq!(
            result,
            Err(ConfigError::InvalidValue(CLTERMUX_INBOUND_TOKEN_ENV))
        );
    }

    #[test]
    fn valid_configuration_yields_digest_without_retaining_original() {
        let result = with_env(https_base_url(), VALID_TOKEN, VALID_TOKEN).expect("valid config");
        let config = result.expect("integration enabled");
        assert_eq!(config.base_url.as_str(), "https://cltermux.example.com/");
        assert_eq!(config.outbound_token, VALID_TOKEN);
        assert_eq!(config.allowed_client_ids, vec!["cx_mobile"]);
        assert_eq!(
            config.inbound_token_digest,
            Sha256::digest(VALID_TOKEN.as_bytes()).to_vec()
        );
        let rendered = format!("{config:?}");
        assert!(!rendered.contains(VALID_TOKEN));
        assert!(rendered.contains("REDACTED"));
    }

    fn with_env(
        base_url: String,
        outbound: &str,
        inbound: &str,
    ) -> Result<Option<CltermuxConfig>, ConfigError> {
        // 测试通过临时进程内环境变量隔离；env 改动在断言后恢复，避免污染并行用例。
        let guard = EnvGuard::set(&base_url, outbound, inbound);
        let result = cltermux_config_from_env();
        drop(guard);
        result
    }

    struct EnvGuard {
        originals: [(String, Option<String>); 4],
    }

    impl EnvGuard {
        fn set(base_url: &str, outbound: &str, inbound: &str) -> Self {
            let names = [
                CLTERMUX_BASE_URL_ENV,
                CLTERMUX_OUTBOUND_TOKEN_ENV,
                CLTERMUX_INBOUND_TOKEN_ENV,
                CLTERMUX_ALLOWED_CLIENTS_ENV,
            ];
            let originals = names.map(|name| (name.to_owned(), env::var(name).ok()));
            unsafe {
                env::set_var(CLTERMUX_BASE_URL_ENV, base_url);
                env::set_var(CLTERMUX_OUTBOUND_TOKEN_ENV, outbound);
                env::set_var(CLTERMUX_INBOUND_TOKEN_ENV, inbound);
                env::set_var(CLTERMUX_ALLOWED_CLIENTS_ENV, "cx_mobile");
            }
            Self { originals }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (name, original) in &self.originals {
                match original {
                    Some(value) => unsafe { env::set_var(name, value) },
                    None => unsafe { env::remove_var(name) },
                }
            }
        }
    }
}
