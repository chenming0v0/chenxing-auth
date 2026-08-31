use std::collections::BTreeMap;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

use crate::state::AppState;

fn is_false(value: &bool) -> bool {
    !*value
}

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

#[derive(Deserialize)]
pub struct ConsentForm {
    pub request_id: String,
    pub decision: String,
    pub csrf_token: String,
}

impl fmt::Debug for ConsentForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsentForm")
            .field("request_id", &"<redacted>")
            .field("decision", &self.decision)
            .field("csrf_token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Serialize)]
pub struct PendingAuthorization {
    pub request_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    /// Issuer runtime generation captured when the authorization request began.
    /// Missing on legacy payloads and therefore rejected by continuation paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_generation: Option<i64>,
    /// Normalized OpenID Connect `prompt` value retained across SPA login and consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Maximum permitted authentication age retained across SPA login and consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
    /// A re-authentication request must not be satisfied by rebinding to the
    /// same pre-existing session. The hash is retained only as a comparison
    /// value; the plaintext session token never enters the pending payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reauth_session_token_hash: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub reauth_required: bool,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    /// The issuing browser session token's SHA-256 digest, never the token itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token_hash: Option<String>,
    /// 发起本次授权的浏览器持有者凭据的 SHA-256 摘要（#115）。
    ///
    /// 防的是 OAuth login CSRF / 请求固定攻击：`request_id` 走 URL 查询参数，
    /// 可能通过 Referer、浏览器历史或分享链接泄露。没有这个字段时，任何持有
    /// `request_id` 的已登录攻击者都能把 `session_token_hash = None` 的 pending 请求绑到
    /// 自己的会话上并批准，把受害者登录进攻击者账号。
    ///
    /// 只存摘要，不存原值：Redis 泄露不足以伪造 holder Cookie。原值仅存在于
    /// 浏览器的 HttpOnly Cookie 中，不写日志、不写审计、不进任何响应体。
    ///
    /// 反序列化 helper 的 `#[serde(default)]` + `skip_serializing_if` 是 Redis 兼容性要求，不可删除：
    /// - `default`：升级期间在途的旧 pending JSON 没有这个键，缺了它反序列化会
    ///   直接失败，所有在途授权请求全部作废。
    /// - `skip_serializing_if`：保持旧载荷表示稳定。CAS 身份只看
    ///   `request_id` + `cas_revision`，不再比较完整 JSON。
    ///
    /// 缺失该字段的旧记录在绑定端点上 fail-secure：直接拒绝，不留「无 holder
    /// 即放行」的绕过窗口。代价是升级瞬间在途的授权请求需要重新发起。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_hash: Option<String>,
    /// Stable CAS generation. Missing on legacy payloads and treated as 0.
    /// In-place rebinds increment this so a stale reader cannot overwrite a
    /// newer binding. Revision 0 is omitted to keep mixed-version JSON stable.
    #[serde(
        default,
        skip_serializing_if = "crate::oauth::cas::is_zero_cas_revision"
    )]
    pub cas_revision: u64,
}

impl fmt::Debug for PendingAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingAuthorization")
            .field("request_id", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("state", &"<redacted>")
            .field("issuer_generation", &self.issuer_generation)
            .field("prompt", &self.prompt)
            .field("max_age", &self.max_age)
            .field(
                "reauth_session_token_hash",
                &self
                    .reauth_session_token_hash
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("reauth_required", &self.reauth_required)
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field("code_challenge", &"<redacted>")
            .field("code_challenge_method", &self.code_challenge_method)
            .field(
                "session_token_hash",
                &self.session_token_hash.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "holder_hash",
                &self.holder_hash.as_ref().map(|_| "<redacted>"),
            )
            .field("cas_revision", &self.cas_revision)
            .finish()
    }
}

#[derive(Deserialize)]
struct PendingAuthorizationPayload {
    request_id: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    #[serde(default)]
    issuer_generation: Option<i64>,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    max_age: Option<u64>,
    #[serde(default)]
    reauth_session_token_hash: Option<String>,
    #[serde(default)]
    reauth_required: bool,
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(default)]
    session_token_hash: Option<String>,
    #[serde(default)]
    holder_hash: Option<String>,
    #[serde(default)]
    cas_revision: u64,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for PendingAuthorizationPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingAuthorizationPayload")
            .field("request_id", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("state", &"<redacted>")
            .field("issuer_generation", &self.issuer_generation)
            .field("prompt", &self.prompt)
            .field("max_age", &self.max_age)
            .field(
                "reauth_session_token_hash",
                &self
                    .reauth_session_token_hash
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("reauth_required", &self.reauth_required)
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field("code_challenge", &"<redacted>")
            .field("code_challenge_method", &self.code_challenge_method)
            .field(
                "session_token_hash",
                &self.session_token_hash.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "holder_hash",
                &self.holder_hash.as_ref().map(|_| "<redacted>"),
            )
            // Legacy payloads may carry the former plaintext session token here.
            .field("extra", &"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for PendingAuthorization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = PendingAuthorizationPayload::deserialize(deserializer)?;
        // Pending requests used the same plaintext field before the hash migration.
        // Reject them before bind/decide can rewrite or consume the payload.
        if payload.extra.contains_key("session_id") {
            return Err(DeError::custom(
                "authorization request contains an unsupported legacy session binding",
            ));
        }
        Ok(Self {
            request_id: payload.request_id,
            client_id: payload.client_id,
            redirect_uri: payload.redirect_uri,
            scope: payload.scope,
            state: payload.state,
            issuer_generation: payload.issuer_generation,
            prompt: payload.prompt,
            max_age: payload.max_age,
            reauth_session_token_hash: payload.reauth_session_token_hash,
            reauth_required: payload.reauth_required,
            nonce: payload.nonce,
            code_challenge: payload.code_challenge,
            code_challenge_method: payload.code_challenge_method,
            session_token_hash: payload.session_token_hash,
            holder_hash: payload.holder_hash,
            cas_revision: payload.cas_revision,
        })
    }
}

impl PendingAuthorization {
    /// Returns whether this pending request belongs to the request's issuer snapshot.
    /// Legacy records without a generation fail closed.
    pub fn is_bound_to_issuer_generation(&self, generation: i64) -> bool {
        self.issuer_generation == Some(generation)
    }
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
            "code_challenge_method": "S256"
        }"#;
        let restored: PendingAuthorization =
            serde_json::from_str(legacy_json).expect("legacy pending must deserialize");
        assert!(restored.holder_hash.is_none());
        assert!(restored.issuer_generation.is_none());
        assert!(
            !restored.is_bound_to_issuer_generation(1),
            "legacy pending requests without an issuer generation must fail closed"
        );
    }

    #[test]
    fn legacy_plaintext_session_binding_is_rejected() {
        let legacy_json = r#"{
            "request_id": "req-legacy",
            "client_id": "client-1",
            "redirect_uri": "https://client.example/callback",
            "scope": "openid",
            "state": "state-legacy",
            "nonce": null,
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
            "session_id": "session-token"
        }"#;
        let error = serde_json::from_str::<PendingAuthorization>(legacy_json)
            .expect_err("legacy plaintext session binding must be rejected");
        assert!(!error.to_string().contains("session-token"));
    }

    /// 回归 #115：`holder_hash: None` 重新序列化后应完全不含该键
    /// （不能是 `"holder_hash":null`）。混部时仍按完整 JSON 比较的旧实例
    /// 才能继续消费 revision 0 的在途载荷。
    #[test]
    fn pending_without_holder_serializes_without_the_key() {
        let pending = PendingAuthorization {
            request_id: "req-no-holder".to_owned(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state-no-holder".to_owned(),
            prompt: None,
            max_age: None,
            reauth_session_token_hash: None,
            reauth_required: false,
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: "S256".to_owned(),
            session_token_hash: None,
            holder_hash: None,
            issuer_generation: None,
            cas_revision: 0,
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
            prompt: None,
            max_age: None,
            reauth_session_token_hash: None,
            reauth_required: false,
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: "S256".to_owned(),
            session_token_hash: None,
            holder_hash: Some("abc123hash".to_owned()),
            issuer_generation: Some(7),
            cas_revision: 0,
        };
        let serialized = serde_json::to_string(&pending).expect("serialize");
        let restored: PendingAuthorization =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(restored.holder_hash.as_deref(), Some("abc123hash"));
        assert_eq!(restored.issuer_generation, Some(7));
        assert!(restored.is_bound_to_issuer_generation(7));
        assert!(!restored.is_bound_to_issuer_generation(8));
        assert_eq!(restored.cas_revision, 0);
        assert!(!serialized.contains("cas_revision"));
    }

    #[test]
    fn pending_preserves_oidc_prompt_and_reauthentication_constraints() {
        let pending = PendingAuthorization {
            request_id: "req-oidc".to_owned(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state-oidc".to_owned(),
            prompt: Some("login".to_owned()),
            max_age: Some(0),
            reauth_session_token_hash: Some("old-session-hash".to_owned()),
            reauth_required: true,
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: "S256".to_owned(),
            session_token_hash: Some("new-session-hash".to_owned()),
            holder_hash: Some("holder-hash".to_owned()),
            issuer_generation: Some(9),
            cas_revision: 1,
        };
        let serialized = serde_json::to_string(&pending).expect("serialize OIDC pending");
        let restored: PendingAuthorization =
            serde_json::from_str(&serialized).expect("deserialize OIDC pending");
        assert_eq!(restored.prompt.as_deref(), Some("login"));
        assert_eq!(restored.max_age, Some(0));
        assert_eq!(
            restored.reauth_session_token_hash.as_deref(),
            Some("old-session-hash")
        );
        assert!(restored.reauth_required);
        assert_eq!(restored.cas_revision, 1);
    }

    #[test]
    fn future_fields_do_not_change_cas_identity() {
        let pending = PendingAuthorization {
            request_id: "req-future".to_owned(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state-future".to_owned(),
            prompt: None,
            max_age: None,
            reauth_session_token_hash: None,
            reauth_required: false,
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: "S256".to_owned(),
            session_token_hash: None,
            holder_hash: None,
            issuer_generation: None,
            cas_revision: 0,
        };
        let mut value = serde_json::to_value(&pending).expect("pending as JSON");
        value
            .as_object_mut()
            .expect("pending serializes to an object")
            .insert("future_field".to_owned(), serde_json::json!({"version": 2}));
        let restored: PendingAuthorization =
            serde_json::from_value(value).expect("future fields must be ignored");
        assert_eq!(restored.request_id, pending.request_id);
        assert_eq!(restored.cas_revision, 0);
    }
}
