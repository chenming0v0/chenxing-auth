//! 审计元数据脱敏。
//!
//! 审计事件的 `metadata` 是自由 JSON，调用点分布在整个 crate 里。这里是唯一的
//! 收口：任何进入 `audit_events` 的元数据都先过一遍本模块，因此"某个 handler
//! 忘了脱敏"不会变成一条持久化的凭据泄露。
//!
//! 两条规则：
//!
//! - **键名匹配**：规范化后（只留 ASCII 字母数字、转小写）落在
//!   [`SENSITIVE_METADATA_KEYS`] 里的键整体删除。白名单
//!   [`SAFE_METADATA_KEYS`] 优先，用于保留 `token_type`、`source_ip` 这类
//!   协议事实 —— 它们的键名像凭据，值不是。
//! - **值内嵌赋值**：形如 `password=...` 的字符串整体替换为 `[REDACTED]`，
//!   覆盖 Cookie 串、查询串和被拼进消息里的凭据。
//!
//! 词表是完整键名而不是片段：用片段匹配会连带删掉 `token_count` 这类计数字段，
//! 让审计失去可用信息。

use serde_json::{Map, Value};

pub(crate) fn redact_metadata(metadata: Value) -> Map<String, Value> {
    let Value::Object(metadata) = metadata else {
        return Map::new();
    };
    match redact_value(Value::Object(metadata)) {
        Some(Value::Object(metadata)) => metadata,
        _ => Map::new(),
    }
}

fn redact_value(value: Value) -> Option<Value> {
    match value {
        Value::Object(object) => Some(Value::Object(
            object
                .into_iter()
                .filter_map(|(key, value)| {
                    if is_sensitive_key(&key) {
                        return None;
                    }
                    Some((key, redact_value(value)?))
                })
                .collect(),
        )),
        Value::Array(values) => Some(Value::Array(
            values.into_iter().filter_map(redact_value).collect(),
        )),
        Value::String(value) if contains_sensitive_assignment(&value) => {
            Some(Value::String("[REDACTED]".to_owned()))
        }
        value => Some(value),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    if SAFE_METADATA_KEYS
        .iter()
        .any(|safe_key| normalized == *safe_key)
    {
        return false;
    }
    SENSITIVE_METADATA_KEYS
        .iter()
        .any(|sensitive_key| normalized == *sensitive_key)
}

fn normalize_key(key: &str) -> String {
    key.bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

const SAFE_METADATA_KEYS: &[&str] = &[
    "accountref",
    "passwordconfigured",
    "sourceip",
    "tokencount",
    "tokentype",
    "tokentypehint",
];

// These are complete metadata keys, rather than fragments. In particular, this keeps
// protocol facts such as token_type and password_configured available to audit queries.
const SENSITIVE_METADATA_KEYS: &[&str] = &[
    "accesstoken",
    "accesstokenhash",
    "apikey",
    "apikeyvalue",
    "authorization",
    "authorizationcode",
    "code",
    "codechallenge",
    "codeverifier",
    "cookie",
    "cookievalue",
    "clientsecret",
    "clientsecrethash",
    "credential",
    "credentialid",
    "credentialvalue",
    "credentials",
    "csrf",
    "csrfcookie",
    "csrftoken",
    "idtoken",
    "jwt",
    "jwttoken",
    "nonce",
    "otp",
    "otpcode",
    "otpsecret",
    "password",
    "passwordhash",
    "passwordvalue",
    "privatekey",
    "privatekeypem",
    "refreshtoken",
    "secret",
    "secretvalue",
    "session",
    "sessioncookie",
    "sessionid",
    "sessiontoken",
    "signature",
    "signaturevalue",
    "state",
    "statetoken",
    "token",
    "tokenvalue",
    "totp",
    "totpcode",
    "totpsecret",
];

fn contains_sensitive_assignment(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (equals_index, byte) in bytes.iter().enumerate() {
        if *byte != b'=' {
            continue;
        }

        let mut key_end = equals_index;
        while key_end > 0 && bytes[key_end - 1].is_ascii_whitespace() {
            key_end -= 1;
        }
        let mut key_start = key_end;
        while key_start > 0 && is_embedded_key_byte(bytes[key_start - 1]) {
            key_start -= 1;
        }
        if key_start == key_end {
            continue;
        }
        if let Ok(key) = std::str::from_utf8(&bytes[key_start..key_end])
            && is_sensitive_key(key)
        {
            return true;
        }
    }
    false
}

fn is_embedded_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 白名单必须压过词表：否则 `token_type` 这类协议事实会被误删，
    /// 审计里只剩"发生了一次 token 操作"而看不出是哪一种。
    #[test]
    fn safe_keys_survive_while_sensitive_keys_are_dropped() {
        let metadata = redact_metadata(serde_json::json!({
            "token_type": "refresh_token",
            "token": "do-not-store",
            "source_ip": "203.0.113.7",
        }));

        assert_eq!(metadata["token_type"], "refresh_token");
        assert_eq!(metadata["source_ip"], "203.0.113.7");
        assert!(metadata.get("token").is_none());
    }

    /// 键名规范化会剥掉分隔符与大小写差异，`Session-ID` 和 `session_id` 同源。
    #[test]
    fn key_matching_ignores_case_and_separators() {
        let metadata = redact_metadata(serde_json::json!({
            "Session-ID": "abc",
            "CSRF_Token": "def",
        }));

        assert!(metadata.is_empty(), "{metadata:?}");
    }

    /// 值里内嵌的赋值同样要脱敏：Cookie 串是最常见的载体。
    #[test]
    fn embedded_assignments_in_values_are_redacted() {
        let metadata =
            redact_metadata(serde_json::json!({"detail": "chenxing_session=abc; path=/"}));

        assert_eq!(metadata["detail"], "[REDACTED]");
    }
}
