//! 不自动 `Debug` / `Serialize` 的敏感字符串包装。
//!
//! 凭据、客户端密钥与协议令牌都必须经过 [`SecretString::expose`] 显式取得明文，
//! 因此它们不会因为一次 `tracing`、`serde_json::to_string` 或 `unwrap` 就进入
//! 日志、审计或错误信息。

use std::fmt;

/// 只在显式调用 [`SecretString::expose`] 时暴露明文的字符串。
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretString;

    #[test]
    fn debug_never_contains_the_plaintext() {
        let secret = SecretString::new("cxap_at_super-secret");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("super-secret"));
        assert_eq!(secret.expose(), "cxap_at_super-secret");
    }
}
