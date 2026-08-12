use std::collections::BTreeMap;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    clock::{Clock, SystemClock},
    sessions::domain::session_token_hash,
};

/// 授权码默认有效期（秒）。运行时优先使用管理设置或启动配置覆盖。
/// 保留此常量作为无状态构造和补偿路径的向后兼容回退值。
pub const AUTHORIZATION_CODE_TTL_SECONDS: u64 = 5 * 60;

#[derive(Clone, Serialize)]
pub struct AuthorizationCode {
    pub value: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    /// 签发该授权码时所依赖的浏览器会话令牌 SHA-256 摘要。
    ///
    /// OIDC Core 3.1.3.2 与 AGENTS.md 都要求授权码绑定 Client、Redirect URI 和
    /// 用户会话：会话被撤销（用户登出）后，授权码必须立即失去兑换能力，否则
    /// 登出只是清了 Cookie，5 分钟 TTL 内的授权码仍能换出 access/refresh token。
    ///
    /// 摘要使用 base64url 无填充编码。`None` 表示降级路径：授权码不是由浏览器会话签发的（例如直接构造的
    /// 测试代码，或升级前写入 Redis 的历史授权码），此时 Token 端点不做会话
    /// 校验，只保留原有的 Client / Redirect URI / PKCE / 用户状态检查。
    ///
    /// 反序列化 helper 的 `#[serde(default)]` + `skip_serializing_if` 是 Redis 兼容性要求，不可删除：
    /// - `default`：升级期间在途的旧授权码 JSON 没有这个键，缺了它反序列化会
    ///   直接失败，所有在途授权码全部作废。
    /// - `skip_serializing_if`：`take_if_matches` 用「重新序列化后与 Redis 中的
    ///   字符串逐字节相等」做原子消费判定。旧载荷解析出 `None` 后如果被写成
    ///   `"session_token_hash":null`，就永远匹配不上原始载荷，旧授权码将无法被消费。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token_hash: Option<String>,
    /// 签发时配额消耗对应的 reservation id（Issue #341）。
    ///
    /// 授权码过期未兑换时，后台 worker 凭这个 id 退还配额；兑换成功时
    /// `take_if_matches` 的 CAS 脚本在同一个原子步骤里把它对应的台账条目
    /// 取消。`None` 表示该授权码没有计量配额（admin Client、无生效套餐）。
    ///
    /// 序列化约定与 `session_token_hash` 相同：`#[serde(default)]` 保证升级
    /// 期间在途的旧授权码可读，`skip_serializing_if` 保证无值时不写键、
    /// CAS 的逐字节相等判定不被破坏。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_reservation_id: Option<String>,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub redeemed_at: Option<OffsetDateTime>,
}

impl fmt::Debug for AuthorizationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationCode")
            .field("value", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("user_id", &self.user_id)
            .field(
                "session_token_hash",
                &self.session_token_hash.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "quota_reservation_id",
                &self.quota_reservation_id.as_ref().map(|_| "<redacted>"),
            )
            .field("scopes", &self.scopes)
            .field("code_challenge", &"<redacted>")
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("redeemed_at", &self.redeemed_at)
            .finish()
    }
}

#[derive(Deserialize)]
struct AuthorizationCodePayload {
    value: String,
    client_id: String,
    redirect_uri: String,
    user_id: String,
    #[serde(default)]
    session_token_hash: Option<String>,
    #[serde(default)]
    quota_reservation_id: Option<String>,
    scopes: Vec<String>,
    code_challenge: String,
    nonce: Option<String>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    redeemed_at: Option<OffsetDateTime>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for AuthorizationCodePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationCodePayload")
            .field("value", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("user_id", &self.user_id)
            .field(
                "session_token_hash",
                &self.session_token_hash.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "quota_reservation_id",
                &self.quota_reservation_id.as_ref().map(|_| "<redacted>"),
            )
            .field("scopes", &self.scopes)
            .field("code_challenge", &"<redacted>")
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("redeemed_at", &self.redeemed_at)
            // Legacy payloads may carry the former plaintext session token here.
            .field("extra", &"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for AuthorizationCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = AuthorizationCodePayload::deserialize(deserializer)?;
        // The old field held a plaintext session token. Reject it before any
        // store caller can reserialize the payload through CAS or restore.
        if payload.extra.contains_key("session_id") {
            return Err(DeError::custom(
                "authorization code contains an unsupported legacy session binding",
            ));
        }
        Ok(Self {
            value: payload.value,
            client_id: payload.client_id,
            redirect_uri: payload.redirect_uri,
            user_id: payload.user_id,
            session_token_hash: payload.session_token_hash,
            quota_reservation_id: payload.quota_reservation_id,
            scopes: payload.scopes,
            code_challenge: payload.code_challenge,
            nonce: payload.nonce,
            created_at: payload.created_at,
            expires_at: payload.expires_at,
            redeemed_at: payload.redeemed_at,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodeError {
    #[error("authorization code has expired")]
    Expired,
    #[error("authorization code was already redeemed")]
    AlreadyRedeemed,
}

impl AuthorizationCode {
    pub fn new(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
    ) -> Self {
        Self::new_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            SystemClock.now(),
        )
    }

    pub fn new_at(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        now: OffsetDateTime,
    ) -> Self {
        Self::new_with_nonce_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            None,
            None,
            now,
        )
    }

    /// Hashes the optional runtime session token before constructing the payload.
    pub fn new_with_nonce(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_token: Option<String>,
    ) -> Self {
        Self::new_with_nonce_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_token,
            SystemClock.now(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_nonce_at(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_token: Option<String>,
        now: OffsetDateTime,
    ) -> Self {
        Self::new_with_nonce_and_ttl_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_token,
            AUTHORIZATION_CODE_TTL_SECONDS,
            now,
        )
    }

    /// 与 `new_with_nonce` 相同，但允许指定 TTL（#121：来自 `AppConfig::security_limits`）。
    // 授权码的元数据字段多，打包成结构体带来的名义上的"清晰度"不抵消每次调用
    // 都要构造临时结构体的冗余；客户端只有 authorization_code_handlers 一处，故维持现状。
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_nonce_and_ttl_at(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_token: Option<String>,
        ttl_seconds: u64,
        now: OffsetDateTime,
    ) -> Self {
        Self::new_with_nonce_and_ttl_at_hashed(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_token.map(|token| session_token_hash(&token)),
            ttl_seconds,
            now,
        )
    }

    /// Construct from a digest already carried by the validated OAuth request.
    ///
    /// 签发时刻由调用方传入（Token 授权路径经 `AppState` 的共享时钟），
    /// 保证 `created_at` / `expires_at` 与 store 保存时的 TTL 计算同源。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_nonce_and_ttl_with_session_hash_at(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_token_hash: Option<String>,
        ttl_seconds: u64,
        now: OffsetDateTime,
    ) -> Self {
        Self::new_with_nonce_and_ttl_at_hashed(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_token_hash,
            ttl_seconds,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_nonce_and_ttl_at_hashed(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_token_hash: Option<String>,
        ttl_seconds: u64,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            value: format!("cx-code-{}", Uuid::new_v4().simple()),
            client_id,
            redirect_uri,
            user_id,
            session_token_hash,
            quota_reservation_id: None,
            scopes,
            code_challenge,
            nonce,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_seconds as i64),
            redeemed_at: None,
        }
    }

    pub fn redeem_at(&mut self, now: OffsetDateTime) -> Result<(), CodeError> {
        if self.redeemed_at.is_some() {
            return Err(CodeError::AlreadyRedeemed);
        }
        if now >= self.expires_at {
            return Err(CodeError::Expired);
        }
        self.redeemed_at = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorizationCode;
    use crate::sessions::domain::session_token_hash;
    use time::{Duration, OffsetDateTime};

    fn code_with_session(session_token: Option<&str>) -> AuthorizationCode {
        AuthorizationCode::new_with_nonce(
            "cx_project".to_owned(),
            "https://project.example/callback".to_owned(),
            "7".to_owned(),
            vec!["openid".to_owned()],
            "challenge".to_owned(),
            None,
            session_token.map(str::to_owned),
        )
    }

    #[test]
    fn explicit_time_constructor_sets_creation_and_expiry_times() {
        let created_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(123);
        let code = AuthorizationCode::new_with_nonce_and_ttl_at(
            "cx_project".to_owned(),
            "https://project.example/callback".to_owned(),
            "7".to_owned(),
            vec!["openid".to_owned()],
            "challenge".to_owned(),
            None,
            None,
            60,
            created_at,
        );

        assert_eq!(code.created_at, created_at);
        assert_eq!(code.expires_at, created_at + Duration::seconds(60));
    }

    /// 构造升级前的授权码 JSON：把当前的会话摘要键从载荷里删掉。
    ///
    /// 不写死时间戳字面量——`time` 只启用了 `serde` 特性（没有
    /// `serde-human-readable`），`OffsetDateTime` 的序列化形式不是 RFC 3339
    /// 字符串，硬编码字面量会与实际格式失配。
    fn legacy_code_json(code: &AuthorizationCode) -> String {
        let serialized = serde_json::to_string(code).expect("serialize code");
        let hash = serde_json::to_string(
            code.session_token_hash
                .as_ref()
                .expect("bound code has a session hash"),
        )
        .expect("serialize session hash");
        let field = format!("\"session_token_hash\":{hash}");
        let legacy = serialized.replace(&format!("{field},"), "");
        assert_ne!(legacy, serialized, "session hash field must be removed");
        legacy
    }

    /// 向后兼容回归：升级期间 Redis 里在途的授权码没有会话摘要键。
    /// 少了 `#[serde(default)]` 就会反序列化失败，所有在途授权码直接作废。
    #[test]
    fn legacy_code_without_a_session_hash_deserializes_as_none() {
        let code = code_with_session(Some("session-token"));
        let legacy_json = legacy_code_json(&code);
        // 前置条件：构造出的旧载荷确实不含该键，否则这个回归测试没有意义。
        assert!(!legacy_json.contains("session_token_hash"));

        let restored: AuthorizationCode =
            serde_json::from_str(&legacy_json).expect("legacy code must remain readable");

        assert!(restored.session_token_hash.is_none());
        assert_eq!(restored.value, code.value);
        assert_eq!(restored.client_id, code.client_id);
        assert_eq!(restored.redirect_uri, code.redirect_uri);
        assert_eq!(restored.user_id, code.user_id);
        assert_eq!(restored.scopes, code.scopes);
        assert_eq!(restored.code_challenge, code.code_challenge);
        assert_eq!(restored.created_at, code.created_at);
        assert_eq!(restored.expires_at, code.expires_at);
    }

    /// `take_if_matches` 靠「重新序列化 == Redis 中的原始字符串」做原子消费。
    /// 无会话的授权码必须省略该键而不是写成 `null`，否则旧授权码永远消费不掉。
    #[test]
    fn code_without_a_session_hash_round_trips_byte_identically() {
        let code = code_with_session(None);
        let payload = serde_json::to_string(&code).expect("serialize code");
        assert!(!payload.contains("session_token_hash"));

        let restored: AuthorizationCode = serde_json::from_str(&payload).expect("deserialize code");

        assert_eq!(
            serde_json::to_string(&restored).expect("reserialize code"),
            payload
        );
    }

    /// 旧载荷解析后重新序列化不得带回会话摘要键或任何旧凭据。
    #[test]
    fn legacy_code_payload_reserializes_without_a_session_binding() {
        let legacy_json = legacy_code_json(&code_with_session(Some("session-token")));
        let restored: AuthorizationCode =
            serde_json::from_str(&legacy_json).expect("legacy code payload");

        let reserialized = serde_json::to_string(&restored).expect("reserialize legacy code");
        assert_eq!(reserialized, legacy_json);
        assert!(!reserialized.contains("session_token_hash"));
        assert!(!reserialized.contains("session-token"));
    }

    #[test]
    fn legacy_plaintext_session_binding_is_rejected() {
        let mut value = serde_json::to_value(code_with_session(None)).expect("code as JSON value");
        value
            .as_object_mut()
            .expect("code serializes to a JSON object")
            .insert(
                "session_id".to_owned(),
                serde_json::Value::String("session-token".to_owned()),
            );
        let error = serde_json::from_value::<AuthorizationCode>(value)
            .expect_err("legacy plaintext session binding must be rejected");
        assert!(!error.to_string().contains("session-token"));
    }

    /// 有会话时摘要键必须真的写进载荷，否则 Token 端点拿不到会话、绑定形同虚设。
    #[test]
    fn code_with_a_session_hash_persists_without_plaintext() {
        let code = code_with_session(Some("session-token"));
        let payload = serde_json::to_string(&code).expect("serialize code");
        let hash = session_token_hash("session-token");
        assert!(payload.contains(&hash));
        assert!(!payload.contains("session-token"));

        let restored: AuthorizationCode = serde_json::from_str(&payload).expect("deserialize code");

        assert_eq!(restored.session_token_hash.as_deref(), Some(hash.as_str()));
    }
}
