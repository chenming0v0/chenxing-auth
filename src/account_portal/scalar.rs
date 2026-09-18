//! Account Provider v1 的标量类型与取值校验。
//!
//! 这里集中协议里最容易出错的三类标量：规范 HTTPS origin、UTC RFC3339 时间戳、
//! 有限安全 JSON 数字。它们都从 `serde_json::Value` 显式解析成受约束的新类型，
//! 上层拿不到未经验证的原始 JSON 树。

use serde_json::{Map, Value};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};
use url::Url;

use super::error::ProtocolError;

/// JSON Schema 允许的最大安全整数（`2^53 - 1`），单位统一为秒或纯计数。
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// provider 响应体上限。解析入口自己也检查，不能只依赖 HTTP 传输层。
pub const MAX_RESPONSE_BYTES: usize = 128 * 1024;

/// 解析 JSON 响应体：先强制 128 KiB 上限，再解析。
///
/// 所有 `parse(bytes)` 入口都必须走这里，这样即使调用方绕过 HTTP transport
/// （例如直接喂夹具或未来读本地缓存）也受同一字节上限约束。
pub fn parse_json_limited(bytes: &[u8]) -> Result<Value, ProtocolError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ProtocolError::PayloadTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| ProtocolError::MalformedJson)
}

/// 取出必填字段，缺失即报错（字段名是静态字面量，不含原始值）。
pub fn required<'a>(
    map: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Value, ProtocolError> {
    map.get(field).ok_or(ProtocolError::MissingRequired(field))
}

/// 读取字符串并同时校验 UTF-8 字节上限（schema 的 `maxLength` 计码点，不够）。
pub fn bounded_string(
    value: &Value,
    field: &'static str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<String, ProtocolError> {
    let text = value.as_str().ok_or(ProtocolError::UnexpectedType(field))?;
    if text.len() < min_bytes {
        return Err(ProtocolError::InvalidValue(field));
    }
    if text.len() > max_bytes {
        return Err(ProtocolError::ByteLimitExceeded(field));
    }
    Ok(text.to_owned())
}

/// 读取必填字符串并校验字节长度。
pub fn required_string(
    map: &Map<String, Value>,
    field: &'static str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<String, ProtocolError> {
    bounded_string(required(map, field)?, field, min_bytes, max_bytes)
}

/// 协议 `fields[].value` 里的有限安全 JSON number。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SafeNumber(f64);

impl SafeNumber {
    pub fn parse(value: &Value, field: &'static str) -> Result<Self, ProtocolError> {
        let number = value.as_f64().ok_or(ProtocolError::UnexpectedType(field))?;
        if !number.is_finite() || number.abs() > MAX_SAFE_INTEGER as f64 {
            return Err(ProtocolError::InvalidValue(field));
        }
        Ok(Self(number))
    }

    pub fn get(self) -> f64 {
        self.0
    }
}

/// 读取非负整数秒（`duration`、`remaining_seconds`、`expires_in` 共用）。
pub fn parse_seconds(value: &Value, field: &'static str) -> Result<u64, ProtocolError> {
    let seconds = value.as_u64().ok_or(ProtocolError::UnexpectedType(field))?;
    if seconds > MAX_SAFE_INTEGER {
        return Err(ProtocolError::InvalidValue(field));
    }
    Ok(seconds)
}

/// RFC3339 UTC 时间戳。非 UTC 偏移（例如 `+08:00`）按协议拒绝。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtcTime(OffsetDateTime);

impl UtcTime {
    pub fn parse_rfc3339(value: &str) -> Result<Self, ProtocolError> {
        let parsed = OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| ProtocolError::InvalidValue("timestamp"))?;
        if parsed.offset() != UtcOffset::UTC {
            return Err(ProtocolError::InvalidValue("timestamp"));
        }
        Ok(Self(parsed))
    }

    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    pub fn from_datetime(value: OffsetDateTime) -> Self {
        Self(value)
    }

    pub fn as_datetime(self) -> OffsetDateTime {
        self.0
    }

    /// 序列化为 RFC3339 UTC 字符串（`Z`）。仅用于加密落库的显式导出路径。
    pub fn to_rfc3339(self) -> String {
        self.0.format(&Rfc3339).unwrap_or_default()
    }
}

/// 从 JSON 值读取 RFC3339 UTC 字符串。
pub fn parse_utc(value: &Value, field: &'static str) -> Result<UtcTime, ProtocolError> {
    let text = value.as_str().ok_or(ProtocolError::UnexpectedType(field))?;
    UtcTime::parse_rfc3339(text).map_err(|_| ProtocolError::InvalidValue(field))
}

/// 从 JSON 值读取协议要求的 HTTPS URL（无 userinfo、≤2048 字节）。
pub fn parse_https_url(value: &Value, field: &'static str) -> Result<Url, ProtocolError> {
    let text = value.as_str().ok_or(ProtocolError::UnexpectedType(field))?;
    if text.len() > 2048 {
        return Err(ProtocolError::ByteLimitExceeded(field));
    }
    if text.chars().any(char::is_whitespace) || authority_contains_userinfo(text) {
        return Err(ProtocolError::InvalidValue(field));
    }
    let url = Url::parse(text).map_err(|_| ProtocolError::InvalidValue(field))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ProtocolError::InvalidValue(field));
    }
    Ok(url)
}

/// schema 的 URL pattern 不允许 authority 段出现 `@`。`Url` 会把空 userinfo 也吃掉，
/// 所以这里按原始字符串补一层判定。
fn authority_contains_userinfo(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains('@')
}

/// 提供方规范 HTTPS origin。
///
/// 协议要求配置值与提供方声明**逐字一致**：本类型同时保存经校验的**原始字符串**
/// 和解析后的 [`Url`]，相等性、比较与落库一律使用原始字符串，解析 URL 只用于构建
/// 固定请求路径。因此 `https://provider.example.com`、`https://provider.example.com:443`
/// 与 `https://Provider.Example.com` 是三个不同的 issuer，不做 host 大小写或默认端口
/// 归一化。
///
/// 拒绝一切 `url::Url` 会替我们「修复」的非规范写法：前后空白、反斜杠、非小写
/// `https://` 前缀、任何路径、裸 query/fragment、以及任何形式 userinfo（含空 `@`）。
#[derive(Debug, Clone)]
pub struct Issuer {
    original: String,
    url: Url,
}

impl PartialEq for Issuer {
    fn eq(&self, other: &Self) -> bool {
        self.original == other.original
    }
}

impl Eq for Issuer {}

impl Issuer {
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        // 形态先按原始字符串严格判定：Url::parse 会把大小写 scheme、反斜杠等
        // 悄悄规范化，不能让它把不合规输入变成「合法」。
        if value.is_empty()
            || value.len() > 255
            || value.trim() != value
            || !value.starts_with("https://")
            || value.chars().any(|character| {
                character.is_whitespace() || character.is_control() || character == '\\'
            })
        {
            return Err(ProtocolError::InvalidValue("issuer"));
        }
        let authority = &value["https://".len()..];
        // 无路径、无 query/fragment、无 userinfo（含空 `@`）。空 authority 也在此拒绝。
        if authority.is_empty()
            || authority.ends_with(':')
            || authority.contains(['/', '?', '#', '@'])
        {
            return Err(ProtocolError::InvalidValue("issuer"));
        }
        let url = Url::parse(value).map_err(|_| ProtocolError::InvalidValue("issuer"))?;
        let is_origin = url.scheme() == "https"
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && (url.path() == "/" || url.path().is_empty());
        if !is_origin {
            return Err(ProtocolError::InvalidValue("issuer"));
        }
        Ok(Self {
            original: value.to_owned(),
            url,
        })
    }

    /// 经过验证的原始 issuer 字符串。比较与落库用这个值。
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// 解析后的 URL，仅用于拼接固定请求路径。
    pub fn as_url(&self) -> &Url {
        &self.url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_preserves_the_exact_original_string() {
        let plain = Issuer::parse("https://provider.example.com").expect("origin");
        assert_eq!(plain.as_str(), "https://provider.example.com");

        // Go 侧合法的显式默认端口与 host 大小写都保留原文。
        let explicit_port = Issuer::parse("https://provider.example.com:443").expect("origin");
        assert_eq!(explicit_port.as_str(), "https://provider.example.com:443");
        let mixed_case = Issuer::parse("https://Provider.Example.com").expect("origin");
        assert_eq!(mixed_case.as_str(), "https://Provider.Example.com");

        // 原文不同就不视为同一个 issuer，不做任何归一化。
        assert_ne!(plain, explicit_port);
        assert_ne!(plain, mixed_case);
        assert_eq!(
            plain,
            Issuer::parse("https://provider.example.com").expect("origin")
        );
    }

    #[test]
    fn issuer_rejects_non_canonical_and_fixable_forms() {
        for value in [
            // scheme
            "http://provider.example.com",
            "HTTPS://provider.example.com",
            "https:/provider.example.com",
            // 尾斜杠与任何路径
            "https://provider.example.com/",
            "https://provider.example.com//",
            "https://provider.example.com/oauth",
            // 前后空白与空串
            " https://provider.example.com",
            "https://provider.example.com ",
            "\thttps://provider.example.com",
            "",
            // 裸 query/fragment
            "https://provider.example.com?x=1",
            "https://provider.example.com#frag",
            // userinfo（含空 `@`）
            "https://user:pass@provider.example.com",
            "https://user@provider.example.com",
            "https://@provider.example.com",
            // 反斜杠
            "https://provider.example.com\\@evil.example.com",
            "https://provider.example.com\\path",
            // 空 authority / 尾冒号
            "https://",
            "https://provider.example.com:",
        ] {
            assert!(Issuer::parse(value).is_err(), "`{value}` must be rejected");
        }
    }

    #[test]
    fn issuer_bounds_length_and_rejects_bad_ports() {
        assert!(Issuer::parse(&format!("https://{}", "a".repeat(300))).is_err());
        assert!(Issuer::parse("https://provider.example.com:99999").is_err());
    }

    #[test]
    fn utc_timestamp_rejects_non_utc_offsets() {
        assert!(UtcTime::parse_rfc3339("2026-09-18T00:00:00Z").is_ok());
        assert!(UtcTime::parse_rfc3339("2026-09-18T00:00:00+00:00").is_ok());
        assert!(UtcTime::parse_rfc3339("2026-09-18T08:00:00+08:00").is_err());
        assert!(UtcTime::parse_rfc3339("not-a-time").is_err());
    }

    #[test]
    fn https_url_rejects_userinfo_and_plain_http() {
        assert!(parse_https_url(&serde_json::json!("https://a.example/x"), "field").is_ok());
        assert!(parse_https_url(&serde_json::json!("http://a.example/x"), "field").is_err());
        assert!(parse_https_url(&serde_json::json!("https://user@a.example/x"), "field").is_err());
    }

    #[test]
    fn seconds_reject_floats_negatives_and_huge_values() {
        assert_eq!(
            parse_seconds(&serde_json::json!(900), "field").expect("seconds"),
            900
        );
        assert!(parse_seconds(&serde_json::json!(100.0), "field").is_err());
        assert!(parse_seconds(&serde_json::json!(-1), "field").is_err());
        assert!(parse_seconds(&serde_json::json!(1e300), "field").is_err());
    }
}
