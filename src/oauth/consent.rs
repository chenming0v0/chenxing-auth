use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    Approve,
    Deny,
}

pub fn parse_decision(value: &str) -> Option<ConsentDecision> {
    match value {
        "approve" => Some(ConsentDecision::Approve),
        "deny" => Some(ConsentDecision::Deny),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub request_id: String,
    pub decision: String,
    pub csrf_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAuthorization {
    pub request_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub session_id: Option<String>,
    /// 发起本次授权的浏览器持有者凭据的 SHA-256 摘要（#115）。
    ///
    /// 防的是 OAuth login CSRF / 请求固定攻击：`request_id` 走 URL 查询参数，
    /// 可能通过 Referer、浏览器历史或分享链接泄露。没有这个字段时，任何持有
    /// `request_id` 的已登录攻击者都能把 `session_id = None` 的 pending 请求绑到
    /// 自己的会话上并批准，把受害者登录进攻击者账号。
    ///
    /// 只存摘要，不存原值：Redis 泄露不足以伪造 holder Cookie。原值仅存在于
    /// 浏览器的 HttpOnly Cookie 中，不写日志、不写审计、不进任何响应体。
    ///
    /// `#[serde(default)]` + `skip_serializing_if` 是 Redis 兼容性要求，不可删除：
    /// - `default`：升级期间在途的旧 pending JSON 没有这个键，缺了它反序列化会
    ///   直接失败，所有在途授权请求全部作废。
    /// - `skip_serializing_if`：`take_if_matches` / `replace_if_matches` 用「重新
    ///   序列化后与 Redis 中的字符串逐字节相等」做原子消费判定。旧载荷解析出
    ///   `None` 后如果被写成 `"holder_hash":null`，就永远匹配不上原始载荷，
    ///   升级前创建的 pending 请求将无法被批准或消费。
    ///
    /// 缺失该字段的旧记录在绑定端点上 fail-secure：直接拒绝，不留「无 holder
    /// 即放行」的绕过窗口。代价是升级瞬间在途的授权请求需要重新发起。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_hash: Option<String>,
}

/// Returns whether a pending authorization request still exists in the store.
///
/// External identity provider login checks this before starting an OAuth dance so
/// that a stale `request_id` query parameter is rejected instead of silently
/// losing the pending authorization.
pub async fn pending_request_exists(state: &AppState, request_id: &str) -> bool {
    state
        .authorization_requests
        .find(request_id)
        .await
        .ok()
        .flatten()
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::PendingAuthorization;

    /// 回归 #115：holder_hash 升级前的旧 pending JSON 不含该键，
    /// 反序列化时应填充为 `None`，不能导致解析失败。
    #[test]
    fn legacy_pending_without_holder_hash_deserializes_as_none() {
        let legacy_json = r#"{
            "request_id": "req-legacy",
            "client_id": "client-1",
            "redirect_uri": "https://client.example/callback",
            "scope": "openid",
            "state": "state-legacy",
            "nonce": null,
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
            "session_id": null
        }"#;
        let restored: PendingAuthorization =
            serde_json::from_str(legacy_json).expect("legacy pending must deserialize");
        assert!(restored.holder_hash.is_none());
    }

    /// 回归 #115：`holder_hash: None` 重新序列化后应完全不含该键
    /// （不能是 `"holder_hash":null`），保证 `take_if_matches` 的逐字节相等判定
    /// 对旧记录仍然有效。
    #[test]
    fn pending_without_holder_serializes_without_the_key() {
        let pending = PendingAuthorization {
            request_id: "req-no-holder".to_owned(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state-no-holder".to_owned(),
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: "S256".to_owned(),
            session_id: None,
            holder_hash: None,
        };
        let serialized = serde_json::to_string(&pending).expect("serialize pending");
        // 关键：JSON 中不能出现 `"holder_hash":null` 或 `"holder_hash":`，
        // 否则与旧载荷字节不匹配，导致原子消费失败。
        assert!(!serialized.contains("holder_hash"));
    }

    /// 回归 #115：有 holder_hash 的新 pending 往返后保持字段存在。
    #[test]
    fn pending_with_holder_round_trips() {
        let pending = PendingAuthorization {
            request_id: "req-with-holder".to_owned(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state-with-holder".to_owned(),
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: "S256".to_owned(),
            session_id: None,
            holder_hash: Some("abc123hash".to_owned()),
        };
        let serialized = serde_json::to_string(&pending).expect("serialize");
        let restored: PendingAuthorization = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(restored.holder_hash.as_deref(), Some("abc123hash"));
    }
}
