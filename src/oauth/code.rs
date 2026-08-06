use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::clock::{Clock, SystemClock};

/// 授权码默认有效期（秒）。可通过 `AUTHORIZATION_CODE_TTL_SECONDS` 配置覆盖（#121）。
/// 保留此常量作为向后兼容的回退值（token_handlers.rs 补偿路径使用它）。
pub const AUTHORIZATION_CODE_TTL_SECONDS: u64 = 5 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub value: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    /// 签发该授权码时所依赖的浏览器会话令牌。
    ///
    /// OIDC Core 3.1.3.2 与 AGENTS.md 都要求授权码绑定 Client、Redirect URI 和
    /// 用户会话：会话被撤销（用户登出）后，授权码必须立即失去兑换能力，否则
    /// 登出只是清了 Cookie，5 分钟 TTL 内的授权码仍能换出 access/refresh token。
    ///
    /// `None` 表示降级路径：授权码不是由浏览器会话签发的（例如直接构造的
    /// 测试代码，或升级前写入 Redis 的历史授权码），此时 Token 端点不做会话
    /// 校验，只保留原有的 Client / Redirect URI / PKCE / 用户状态检查。
    ///
    /// `#[serde(default)]` + `skip_serializing_if` 是 Redis 兼容性要求，不可删除：
    /// - `default`：升级期间在途的旧授权码 JSON 没有这个键，缺了它反序列化会
    ///   直接失败，所有在途授权码全部作废。
    /// - `skip_serializing_if`：`take_if_matches` 用「重新序列化后与 Redis 中的
    ///   字符串逐字节相等」做原子消费判定。旧载荷解析出 `None` 后如果被写成
    ///   `"session_id":null`，就永远匹配不上原始载荷，旧授权码将无法被消费。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub redeemed_at: Option<OffsetDateTime>,
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

    pub fn new_with_nonce(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_id: Option<String>,
    ) -> Self {
        Self::new_with_nonce_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_id,
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
        session_id: Option<String>,
        now: OffsetDateTime,
    ) -> Self {
        Self::new_with_nonce_and_ttl_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_id,
            AUTHORIZATION_CODE_TTL_SECONDS,
            now,
        )
    }

    /// 与 `new_with_nonce` 相同，但允许指定 TTL（#121：来自 `AppConfig::security_limits`）。
    // 授权码的元数据字段多，打包成结构体带来的名义上的"清晰度"不抵消每次调用
    // 都要构造临时结构体的冗余；客户端只有 authorization_code_handlers 一处，故维持现状。
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_nonce_and_ttl(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_id: Option<String>,
        ttl_seconds: u64,
    ) -> Self {
        Self::new_with_nonce_and_ttl_at(
            client_id,
            redirect_uri,
            user_id,
            scopes,
            code_challenge,
            nonce,
            session_id,
            ttl_seconds,
            SystemClock.now(),
        )
    }

    /// Pure constructor variant with an explicit issuance time.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_nonce_and_ttl_at(
        client_id: String,
        redirect_uri: String,
        user_id: String,
        scopes: Vec<String>,
        code_challenge: String,
        nonce: Option<String>,
        session_id: Option<String>,
        ttl_seconds: u64,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            value: format!("cx-code-{}", Uuid::new_v4().simple()),
            client_id,
            redirect_uri,
            user_id,
            session_id,
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
    use time::{Duration, OffsetDateTime};

    fn code_with_session(session_id: Option<String>) -> AuthorizationCode {
        AuthorizationCode::new_with_nonce(
            "cx_project".to_owned(),
            "https://project.example/callback".to_owned(),
            "7".to_owned(),
            vec!["openid".to_owned()],
            "challenge".to_owned(),
            None,
            session_id,
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

    /// 构造升级前的授权码 JSON：把 `session_id` 键从当前载荷里删掉。
    ///
    /// 不写死时间戳字面量——`time` 只启用了 `serde` 特性（没有
    /// `serde-human-readable`），`OffsetDateTime` 的序列化形式不是 RFC 3339
    /// 字符串，硬编码字面量会与实际格式失配。
    fn legacy_code_json(code: &AuthorizationCode) -> String {
        let mut value = serde_json::to_value(code).expect("code as JSON value");
        value
            .as_object_mut()
            .expect("code serializes to a JSON object")
            .remove("session_id");
        value.to_string()
    }

    /// 向后兼容回归：升级期间 Redis 里在途的授权码没有 `session_id` 键。
    /// 少了 `#[serde(default)]` 就会反序列化失败，所有在途授权码直接作废。
    #[test]
    fn legacy_code_without_a_session_id_deserializes_as_none() {
        let code = code_with_session(Some("session-token".to_owned()));
        let legacy_json = legacy_code_json(&code);
        // 前置条件：构造出的旧载荷确实不含该键，否则这个回归测试没有意义。
        assert!(!legacy_json.contains("session_id"));

        let restored: AuthorizationCode =
            serde_json::from_str(&legacy_json).expect("legacy code must remain readable");

        assert!(restored.session_id.is_none());
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
    fn code_without_a_session_id_round_trips_byte_identically() {
        let code = code_with_session(None);
        let payload = serde_json::to_string(&code).expect("serialize code");
        assert!(!payload.contains("session_id"));

        let restored: AuthorizationCode = serde_json::from_str(&payload).expect("deserialize code");

        assert_eq!(
            serde_json::to_string(&restored).expect("reserialize code"),
            payload
        );
    }

    /// 旧载荷解析后重新序列化必须与原始字符串完全一致，
    /// 否则补偿路径 `restore` 与 `take_if_matches` 会互相错配。
    #[test]
    fn legacy_code_payload_reserializes_to_the_original_bytes() {
        let legacy_json = legacy_code_json(&code_with_session(Some("session-token".to_owned())));
        let restored: AuthorizationCode =
            serde_json::from_str(&legacy_json).expect("legacy code payload");

        // serde 的字段顺序按结构体声明顺序输出，而测试数据是按字母序构造的，
        // 所以按结构比较而不是按字节比较：语义等价才是补偿路径需要的不变量。
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &serde_json::to_string(&restored).expect("reserialize legacy code")
            )
            .expect("reserialized value"),
            serde_json::from_str::<serde_json::Value>(&legacy_json).expect("legacy value")
        );
    }

    /// 有会话时该键必须真的写进载荷，否则 Token 端点拿不到会话、绑定形同虚设。
    #[test]
    fn code_with_a_session_id_persists_the_binding() {
        let code = code_with_session(Some("session-token".to_owned()));
        let payload = serde_json::to_string(&code).expect("serialize code");
        assert!(payload.contains("session-token"));

        let restored: AuthorizationCode = serde_json::from_str(&payload).expect("deserialize code");

        assert_eq!(restored.session_id.as_deref(), Some("session-token"));
    }
}
